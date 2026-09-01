//! The Sage-parity RPC backend + the transport-independent dispatch.
//!
//! [`WalletBackend`] ties the local DB ([`crate::sage::db`]), the fallback tier
//! ([`crate::sage::fallback`]) and the sync-state gate ([`crate::sage::routing`]) together
//! and answers the **core READ methods** (design Part F MUST, this PR's scope). Every
//! wallet-data read chooses its source via [`routing::route`]; the answer is mapped into
//! the Sage wire types ([`crate::sage::types`]) so it is byte-compatible with Sage.
//!
//! [`WalletBackend::dispatch`] is the ONE handler set both transports call (design C.3):
//! `method` + JSON body → `(http_status, body)`. Because both the wallet mTLS listener and
//! the plain-HTTP+CORS browser mirror call this same function, their bodies are
//! byte-identical by construction. Success → `200` + JSON; error → Sage's status (A.3) +
//! the plain-text message.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use serde::Serialize;
use serde_json::Value;

use chia_bls::PublicKey;
use chia_wallet_sdk::driver::Cat;
use chia_wallet_sdk::types::{MAINNET_CONSTANTS, TESTNET11_CONSTANTS};

use super::chain::PushOutcome;
use super::coverage::CoveredSet;
use super::custody::WalletCustody;
use super::db::{
    ClientReservation, CoinRow, OfferDbRow, OptionDbRow, ReserveClientCoinsError, ReservedCoinRow,
    WalletDb,
};
use super::events::EventBus;
use super::fallback::{ChainFallback, FallbackCoin, FallbackCoinSpend};
use super::routing::{self, Source};
use super::singleton::{self, LineageSource, ParentSpend};
use super::spend::{self, required_public_keys, Broadcaster, WalletSigner};
use super::types::*;
use super::{actions, mint, network, offers, options, themes};
use super::{Error, Result};
use dig_node_control_interface::params::{Asset as ControlAsset, AssetId as ControlAssetId};

/// Which asset a [`WalletBackend::balance_for_address`] read totals (#1851), widened from the
/// original XCH-or-$DIG pair to ANY CAT (dig_ecosystem#3077).
///
/// The wire form is [`dig_node_control_interface::params::Asset`]'s — `"xch"`, `"dig"`, or
/// `{"cat":"<64-hex>"}` — and the two types convert into each other rather than each spelling it,
/// so the node cannot parse an asset the published contract does not describe.
///
/// # Why the asset id is CARRIED, not looked up
///
/// Every scoping decision in a read ([`Self::asset_id_hex`] for the DB tier,
/// [`Self::cat_coin_puzzle_hash`] for the hint-blind fallback tier) is derived from this id. A
/// variant that merely NAMED a token would force each derivation to resolve the name to an id
/// separately, and the read would answer a confident empty list for any token a derivation had
/// not been taught about — the silent-wrong-answer this widening exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceAsset {
    /// Native chia (XCH) — no CAT asset id.
    Xch,
    /// A CAT, named by its asset id (TAIL hash).
    Cat(Bytes32),
}

impl From<ControlAsset> for BalanceAsset {
    fn from(asset: ControlAsset) -> Self {
        match asset.asset_id() {
            None => Self::Xch,
            Some(id) => Self::Cat(Bytes32::from(*id.as_bytes())),
        }
    }
}

impl From<BalanceAsset> for ControlAsset {
    fn from(asset: BalanceAsset) -> Self {
        match asset {
            BalanceAsset::Xch => Self::Xch,
            BalanceAsset::Cat(id) => Self::Cat(ControlAssetId::new(id.to_bytes())),
        }
    }
}

impl BalanceAsset {
    /// The $DIG CAT.
    ///
    /// The single spelling of $DIG's TAIL in this module, sourced from
    /// `digstore_chain::dig::DIG_ASSET_ID` so it never drifts from the canonical definition.
    pub const DIG: Self = Self::Cat(digstore_chain::dig::DIG_ASSET_ID);

    /// The CAT TAIL this asset scopes to, or `None` for native XCH.
    ///
    /// [`Self::asset_id_hex`] is its hex rendering and [`Self::cat_coin_puzzle_hash`] its
    /// puzzle-hash rendering; all three must name the same asset or a read can scope its two
    /// tiers to different ones.
    fn cat_asset_id(self) -> Option<Bytes32> {
        match self {
            Self::Xch => None,
            Self::Cat(id) => Some(id),
        }
    }

    /// The CAT asset id (bare lowercase hex) this asset scopes to, or `None` for native XCH
    /// — the `asset_id` argument the DB reads take.
    fn asset_id_hex(self) -> Option<String> {
        self.cat_asset_id().map(hex::encode)
    }

    /// The asset an `asset_id` wire argument names: `None` is native XCH, `Some(hex)` a CAT.
    ///
    /// The INVERSE of [`Self::asset_id_hex`], and the reason it exists is dig-node#306: the
    /// Sage-parity coin reads take an `Option<&str>` while the scoping helpers take a
    /// [`BalanceAsset`], and without this bridge the fallback tier had no way to scope a CAT read
    /// and simply answered with nothing.
    ///
    /// An UNPARSEABLE asset id is an `Err`, never a silent `Xch`. Defaulting a mistyped id to
    /// native XCH is how a caller asking about one token gets a confident answer about a
    /// different one — the same rule `parse_asset_param` states on the control surface.
    fn from_asset_id_hex(asset_id: Option<&str>) -> Result<Self> {
        let Some(id) = asset_id else {
            return Ok(Self::Xch);
        };
        Ok(Self::Cat(parse_puzzle_hash(id)?))
    }

    /// The puzzle hash this asset's coins sit at when owned by `owner_puzzle_hash`, or `None`
    /// for native XCH (whose coins sit at the owner hash itself).
    ///
    /// A CAT coin does NOT live at its owner's p2 puzzle hash: it lives at the OUTER hash that
    /// curries the asset id (TAIL) around that p2 hash, and is merely HINTED to the p2 hash so a
    /// wallet can find it. So this hash is what identifies a coin as belonging to this asset —
    /// the exact fallback-tier equivalent of the DB tier's `hint IN (…) AND asset_id = ?`.
    ///
    /// Built from `digstore_chain::cat::cat_puzzle_hash`, the canonical construction the wallet's
    /// CAT balance, coin reconstruction and send paths all already use. Never hand-rolled here: a
    /// second spelling of a curry is a future byte-drift bug, and this one decides whether money
    /// is counted.
    ///
    /// Fails on an owner hash that is not 32 bytes of hex rather than degrading to "no filter" —
    /// an unusable scoping hash must fail the read, because the alternative is reporting every
    /// hinted coin as this asset (dig_ecosystem#2879).
    fn cat_coin_puzzle_hash(self, owner_puzzle_hash: &str) -> Result<Option<String>> {
        let Some(asset_id) = self.cat_asset_id() else {
            return Ok(None);
        };
        let owner = parse_puzzle_hash(owner_puzzle_hash)?;
        Ok(Some(hex::encode(digstore_chain::cat::cat_puzzle_hash(
            owner, asset_id,
        ))))
    }
}

/// A bare-or-`0x` puzzle-hash hex string as the 32 bytes it denotes.
///
/// An `Err` rather than an `Option` because every caller is inside a read that must FAIL on an
/// unparseable hash: silently treating one as absent would drop the scoping it was needed for.
fn parse_puzzle_hash(ph: &str) -> Result<Bytes32> {
    let bytes = hex::decode(normalize_ph(ph))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| Error::internal(format!("{ph:?} is not a 32-byte puzzle hash")))?;
    Ok(Bytes32::from(bytes))
}

/// A DB coin row as a [`WalletCoin`].
///
/// Fallible because the row stores its amount as a decimal STRING: a value that will not fit is a
/// corrupt row, and a corrupt row must surface as a read failure rather than vanish from the list.
/// A silently dropped coin is the same lie as an empty list — it under-reports what somebody holds.
fn coin_from_row(row: &CoinRow) -> Result<WalletCoin> {
    let amount = row.amount.parse::<u64>().map_err(|e| {
        Error::internal(format!(
            "coin {} has an unrepresentable amount {:?}: {e}",
            row.coin_id, row.amount
        ))
    })?;
    Ok(WalletCoin {
        coin_id: row.coin_id.clone(),
        parent_coin_info: row.parent_coin_info.clone(),
        puzzle_hash: row.puzzle_hash.clone(),
        amount,
        created_height: row.created_height.and_then(|h| u32::try_from(h).ok()),
        spent_height: row.spent_height.and_then(|h| u32::try_from(h).ok()),
    })
}

/// A fallback-tier coin as a [`WalletCoin`]. Infallible: the tier already parsed the amount.
fn coin_from_fallback(coin: &FallbackCoin) -> WalletCoin {
    WalletCoin {
        coin_id: coin.coin_id.clone(),
        parent_coin_info: coin.parent_coin_info.clone(),
        puzzle_hash: coin.puzzle_hash.clone(),
        amount: coin.amount,
        created_height: coin.created_height,
        spent_height: coin.spent_height,
    }
}

/// A spend and the coin record that carries its heights, composed into one answer — and checked
/// against each other on the way ([`WalletBackend::coin_spend`]).
///
/// A record calling the coin UNSPENT while a spend of it exists is a source contradicting itself,
/// so this fails closed rather than emit a spend with an absent or invented `spent_height`. A
/// caller cannot tell an invented height from a real one, so it must never be handed either.
///
/// One function because BOTH the cached and the networked path compose the same pair, and a second
/// spelling of a fail-closed check is a second chance to get it subtly different.
fn composed_spend(
    spend: &FallbackCoinSpend,
    record: &FallbackCoin,
    coin_id: &str,
) -> std::result::Result<WalletCoinSpend, BalanceError> {
    if record.spent_height.is_none() {
        return Err(BalanceError::ReadFailed(format!(
            "chain source reported a spend of {coin_id} while its record calls the coin unspent"
        )));
    }
    Ok(WalletCoinSpend {
        coin: coin_from_fallback(record),
        puzzle_reveal: spend.puzzle_reveal.clone(),
        solution: spend.solution.clone(),
    })
}

/// Why a [`WalletBackend::push_signed_bundle`] could not report a mempool verdict.
///
/// A mempool REFUSAL is deliberately NOT in here: that is a successful call reporting
/// [`PushOutcome::accepted`] `== false`. These are the ways the network was never asked at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError {
    /// The hex did not decode to a streamable `SpendBundle`. Retrying cannot help.
    InvalidBundle(String),
    /// This node has no way to reach a mempool at all.
    NoChainSource,
    /// The bundle spends a coin at one of the NODE's OWN custodied puzzle hashes while
    /// `DIG_WALLET_ENABLE_LIVE_BROADCAST` is off (§18.12). Relaying it would send the node's own
    /// money, which is precisely the question that flag answers `no` to. Retrying cannot help;
    /// the remedy is either a bundle that does not spend the node's coins, or the flag.
    NodeCustodiedSpend,
    /// A mempool could not be reached. The SAME bundle may succeed on a retry.
    Unreachable(String),
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushError::InvalidBundle(e) => write!(f, "{e}"),
            PushError::NoChainSource => {
                f.write_str("this node has no chain source to push through")
            }
            PushError::NodeCustodiedSpend => f.write_str(
                "this bundle spends the node's own custodied coins, and this node may not send \
                 its own money (DIG_WALLET_ENABLE_LIVE_BROADCAST is off)",
            ),
            PushError::Unreachable(e) => write!(f, "{e}"),
        }
    }
}

/// One UNSPENT coin as a chain read saw it (dig_ecosystem#2376).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletCoin {
    /// The coin id (hex, no `0x`).
    pub coin_id: String,
    /// The parent coin's id (hex).
    pub parent_coin_info: String,
    /// The coin's puzzle hash (hex).
    pub puzzle_hash: String,
    /// The amount, in mojos / CAT base units.
    pub amount: u64,
    /// The height the coin was created at, or `None` while it is known only from the mempool.
    pub created_height: Option<u32>,
    /// The height the coin was SPENT at, or `None` while it is unspent.
    ///
    /// `None` is the truthful value for an unspent coin, and every coin an address-scoped read
    /// returns is unspent by construction — but a coin looked up BY ID may well be spent, and that
    /// is the whole point of [`WalletBackend::coin_by_id`]: a mint poll cannot report failure
    /// without seeing that its funding coin went.
    pub spent_height: Option<u32>,
}

/// The UNSPENT coins held at ONE address for one asset, and the tier that saw them
/// (dig_ecosystem#2376).
///
/// An empty `coins` means a chain WAS consulted and the address holds nothing. A read that could
/// not consult a chain is a [`BalanceError`], never an empty list — see
/// [`WalletBackend::coins_for_address`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCoinsResult {
    /// ONE PAGE of the unspent coins, ASCENDING by `coin_id` — a total, stable order, because a
    /// cursor names no position without one.
    pub coins: Vec<WalletCoin>,
    /// Whether [`Self::coins`] is the WHOLE unspent set at this address for this asset.
    ///
    /// Derived from whether rows remain BEYOND the page, never from whether the page filled. The
    /// two differ exactly when the coin count is a multiple of the page size, and getting it wrong
    /// there hands a spend builder a partial coin set that looks complete — it then refuses with a
    /// shortfall that is not true, while the funds sit in the coins that were withheld.
    pub complete: bool,
    /// The last coin in this page — what a caller resumes from — or `None` for an empty page.
    pub cursor: Option<String>,
    /// Which tier produced these coins.
    pub source: Source,
    /// Whether THIS answer is CURRENT — see [`WalletBalanceResult::synced`], of which this is the
    /// unreduced twin and which carries the full contract. `false` beside a [`Self::peak_height`]
    /// is a real coin set as of that height, not an unknown one.
    pub synced: bool,
    /// The chain peak height THIS answer reflects, when known.
    pub peak_height: Option<u32>,
}

/// ONE coin looked up by coin id, or a chain source's report that it has no such coin
/// (dig_ecosystem#2392).
///
/// `coin: None` means a chain source ANSWERED and reported no such coin. It is NOT yet a proof of
/// absence — see [`WalletBackend::coin_by_id`]. Every way of failing to get an answer at all is a
/// [`BalanceError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCoinByIdResult {
    /// The coin, or `None` when a chain source reported none (see the type doc for what that does
    /// and does not prove).
    pub coin: Option<WalletCoin>,
    /// Which tier produced this answer — [`Source::Db`] where the node's own replica held the coin
    /// and was authoritative for it, [`Source::Fallback`] otherwise. See
    /// [`WalletBackend::coin_by_id`] for why a replica MISS is never an answer.
    ///
    /// [`Source::Fallback`] covers BOTH chain sub-tiers — a directly held peer and the coinset
    /// oracle — and this field does not say which one answered THIS read, because the tier
    /// underneath does not report it per call. What the node CAN say is which tier it is in a
    /// position to use: `chia_peer_count` on `control.wallet.syncStatus` (dig_ecosystem#2806).
    /// Naming the sub-tier per read would be a wire-contract change and is not made here.
    pub source: Source,
    /// Whether THIS answer is current: measured against the peers' announced peak on a
    /// [`Source::Db`] answer, and always `false` on a [`Source::Fallback`] one, which the replica
    /// neither produced nor bounds the freshness of.
    pub synced: bool,
    /// The height this answer is as of — the replica's own peak on a [`Source::Db`] answer, and
    /// `None` on a [`Source::Fallback`] one, where a caller bounding confirmations reads
    /// `control.wallet.peak` instead.
    pub peak_height: Option<u32>,
}

/// ONE coin's spend: the coin it consumed, and the two programs that consumed it
/// (dig_ecosystem#2572).
///
/// The coin is a full [`WalletCoin`] rather than a bare parent/puzzle-hash/amount triple, so a
/// caller gets the spent height in the same answer and never has to make a second call to learn
/// WHEN the thing it is looking at happened. Its `spent_height` is non-null by construction — see
/// [`WalletBackend::coin_spend`], which refuses to report a spend of a coin no record calls spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCoinSpend {
    /// The coin this spend consumed. Its `spent_height` is always `Some`.
    pub coin: WalletCoin,
    /// The puzzle reveal: hex of the serialized CLVM program, verified to tree-hash to
    /// `coin.puzzle_hash` before it ever reaches this struct.
    pub puzzle_reveal: String,
    /// The solution the puzzle was run with: hex of the serialized CLVM.
    pub solution: String,
}

/// The spend that spent one coin, or a chain source's report that there is none
/// (dig_ecosystem#2572).
///
/// `spend: None` means a chain ANSWERED: the coin is unspent, or the chain holds no such coin.
/// Every way of failing to get an answer at all is a [`BalanceError`] — see
/// [`WalletBackend::coin_spend`] for why that distinction is money-critical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCoinSpendResult {
    /// The spend, or `None` when a chain source reported none.
    pub spend: Option<WalletCoinSpend>,
    /// Which tier produced this answer. Always [`Source::Fallback`], for the reason
    /// [`WalletCoinByIdResult::source`] records.
    pub source: Source,
    /// Always `false` — no local replica produced this answer.
    pub synced: bool,
    /// Always `None` — a caller bounding confirmations reads `control.wallet.peak` instead.
    pub peak_height: Option<u32>,
}

/// ONE PAGE of the DIRECT children created by spending one coin — one hop (dig_ecosystem#2572).
///
/// An empty `coins` means a chain ANSWERED and that parent created no children it knows of. Every
/// way of failing to get an answer is a [`BalanceError`], never an empty list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCoinsByParentResult {
    /// One page of the parent's direct children, ASCENDING by `coin_id`.
    pub coins: Vec<WalletCoin>,
    /// Whether [`Self::coins`] is the WHOLE child set.
    ///
    /// Derived from whether children remain BEYOND this page, never from whether the page filled.
    /// The two differ exactly when the child count is a multiple of the page size, and getting it
    /// wrong there ends a lineage walk one hop early while looking finished.
    pub complete: bool,
    /// The last child in this page — what a caller resumes from — or `None` for an empty page.
    pub cursor: Option<String>,
    /// Which tier produced this answer. Always [`Source::Fallback`].
    pub source: Source,
    /// Always `false` — no local replica produced this answer.
    pub synced: bool,
    /// Always `None` — a caller bounding confirmations reads `control.wallet.peak` instead.
    pub peak_height: Option<u32>,
}

/// The node's current chain peak (dig_ecosystem#2376).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPeak {
    /// The peak height, or `None` when no source could name one. `None` is UNKNOWN, never zero.
    pub peak_height: Option<u32>,
    /// Whether the node's own replica is caught up to it.
    pub synced: bool,
}

/// The result of a [`WalletBackend::balance_for_address`] read (#1851): the confirmed +
/// pending balance for ONE address, plus the sync context so a caller can tell a
/// fully-synced figure from a still-converging one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletBalanceResult {
    /// Confirmed, spendable balance (unspent, on-chain) in mojos / CAT base units.
    pub balance: u128,
    /// Pending balance: unspent coins not yet confirmed on-chain (in-flight value).
    pub pending: u128,
    /// Which tier actually produced this figure (#2233): [`Source::Db`] — the node's own
    /// chain replica — or [`Source::Fallback`] — a chain source rather than the replica.
    ///
    /// [`Source::Fallback`] is the ROUTING decision, not a party. Underneath it the node asks its
    /// OWN held Chia peers first and reaches the public coinset oracle only when they fail, so
    /// this field alone does not say the address was disclosed off-node — an earlier version of
    /// this doc claimed it did (dig_ecosystem#2806). `chia_peer_count` on
    /// `control.wallet.syncStatus` says which tier the node is in a position to use.
    ///
    /// When a read DOES reach the oracle it discloses the address, the requesting IP and a
    /// timestamp to a third party. That cost is unchanged and is not being talked down — it is
    /// now stated of the reads it is true of, instead of all of them. A node holding zero peers
    /// pays it on every [`Source::Fallback`] answer.
    ///
    /// Additive per §5.1: a consumer that ignores it parses unchanged.
    pub source: Source,
    /// Whether THIS answer is CURRENT — the replica produced it AND the replica is following the
    /// chain right now.
    ///
    /// Both clauses are required. Only a [`Source::Db`] answer can be current, because only that
    /// tier read the local replica: a fallback answer reports `false` however caught-up the DB
    /// happens to be, since the DB's state does not describe an answer the DB did not give
    /// (#2233).
    ///
    /// And a [`Source::Db`] answer is not current merely by being served. The flag that chose the
    /// tier, `initial_sync_complete`, LATCHES — it records that a catch-up once finished — so a
    /// replica hundreds of blocks behind still routes here. `false` alongside a
    /// [`Self::peak_height`] therefore means *this figure is real, and it is as of that height*,
    /// which is a usable answer; it does not mean the figure is unknown (dig_ecosystem#2869).
    pub synced: bool,
    /// The chain peak height THIS answer reflects, when known — `None` for a
    /// [`Source::Fallback`] answer, whose figure came from the oracle's chain view, not
    /// the node's (#2233).
    pub peak_height: Option<u32>,
}

/// Why a [`WalletBackend::balance_for_address`] read could not produce a figure (#1851).
/// Each variant maps to a DISTINCT wire error — never a fabricated `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BalanceError {
    /// The address did not decode as a bech32m Chia address.
    InvalidAddress,
    /// No live chain source could answer a read that required one (an arbitrary, non-wallet
    /// address with no live fallback attached).
    NoChainSource,
    /// The address is the wallet's own, but the local DB has not finished syncing and no
    /// live fallback is attached, so nothing can answer yet.
    NotSynced,
    /// An underlying read (DB query or fallback) errored.
    ReadFailed(String),
    /// The GLOBAL coinset-fallback rate bound (#1957) is exhausted: too many arbitrary-address
    /// reads have hit the expensive fallback in a short window. Defense-in-depth against an
    /// open-read amplification/oracle sweep — the caller should back off and retry. The cheap
    /// local-DB fast path is NEVER subject to this bound.
    RateLimited,
}

/// Static wallet identity + config the read surface needs (derived once at bring-up).
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// The wallet's tracked puzzle hashes (hex) — both hardened AND unhardened HD +
    /// CAT-hint puzzle hashes. Used to scope fallback reads and `check_address`.
    pub puzzle_hashes: Vec<String>,
    /// The wallet's receive address (first unhardened derivation).
    pub receive_address: String,
    /// The address bech32m prefix (`xch` mainnet / `txch` testnet).
    pub address_prefix: String,
    /// The network id (`mainnet` / `testnet11`).
    pub network_id: String,
    /// Public key metadata for `get_key`/`get_keys` (if a wallet is loaded).
    pub key: Option<KeyInfo>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            puzzle_hashes: Vec::new(),
            receive_address: String::new(),
            address_prefix: "xch".to_string(),
            network_id: "mainnet".to_string(),
            key: None,
        }
    }
}

/// Default burst allowance for the open chain-read fallback (#1957): a single caller may hit the
/// expensive tier this many times in a burst before the rate bound engages.
///
/// **Re-calibrated for what a token now BUYS (dig_ecosystem#3035).** When this bound was set, one
/// token bought one HTTP call to a third-party oracle. Since #3032 the arbitrary chain reads are
/// served by the node's own peers, so one token buys a whole corroborated ROUND — up to
/// [`super::peer_reads::dialed`]'s dial budget of `QUORUM_SAMPLE * 3` = 12 dials, then one request
/// to each of [`super::quorum::QUORUM_SAMPLE`] peers, and `control.wallet.coinSpend` spends its
/// single token on two such reads. A token that costs an order of magnitude more work has to be
/// issued an order of magnitude less freely, or the bound is nominal.
///
/// Still sized so no realistic legitimate use is refused: a burst of 16 covers a profile read and
/// the lineage walk behind it, and a replica-served answer never reaches this gate at all.
const DEFAULT_FALLBACK_BURST: f64 = 16.0;

/// Default sustained refill rate (tokens per second) for the open chain-read fallback (#1957):
/// once the burst is spent, fallback reads are admitted at this steady rate.
///
/// Two per second rather than eight, for the reason [`DEFAULT_FALLBACK_BURST`] gives: at up to a
/// dozen peer messages per token, eight tokens a second is a peer-egress amplifier pointed at the
/// node's own quorum. Two sustains a walk without sustaining a sweep.
const DEFAULT_FALLBACK_REFILL_PER_SEC: f64 = 2.0;

/// How long a pushed bundle holds its input coins out of further selection
/// (dig_ecosystem#2763): ten minutes.
///
/// A reservation ALWAYS expires, and the TTL is the backstop rather than the normal path. The
/// normal releases are observational — the coin is seen spent, or the bundle is definitively
/// refused — and this only decides how long a coin stays held when NEITHER of those ever arrives
/// (the node restarts mid-flight, the peer that would have reported the update is dropped, the
/// bundle is silently evicted from the mempool).
///
/// Sized by which failure is worse. Too SHORT re-exposes the defect: the coin is offered again
/// while the original bundle can still be included, and the second spend is refused. Too LONG
/// strands spendable money in a wallet that looks like it has none. Chia blocks are ~52s apart, so
/// ten minutes is roughly a dozen chances for the spend to land — well past the point where a
/// still-unconfirmed bundle is more likely dropped than pending, and short enough that a stranded
/// coin returns on a timescale a user waits out rather than reports as lost.
const RESERVATION_TTL_MS: i64 = 10 * 60 * 1000;

/// The Sage-parity wallet backend.
#[derive(Clone)]
pub struct WalletBackend {
    db: WalletDb,
    fallback: Arc<dyn ChainFallback>,
    config: WalletConfig,
    /// The wallet's signing keys (node-custodied). `None` when no wallet is loaded — spend
    /// building/signing then returns an error (C.6: the extension self-custodies and never
    /// uses this path).
    signer: Option<Arc<WalletSigner>>,
    /// The network broadcaster. `None` in tests/CI so a built spend is NEVER auto-broadcast.
    broadcaster: Option<Arc<dyn Broadcaster>>,
    /// The pusher for ALREADY-SIGNED bundles (dig_ecosystem#2376).
    ///
    /// Deliberately separate from `broadcaster`: that one is attached only when the node may sign
    /// and send its OWN custodied spends, a custody decision that is default-OFF. Relaying a bundle
    /// somebody else signed is a different question and does not turn on the node's own key.
    pusher: Option<Arc<dyn super::chain::SignedBundlePusher>>,
    /// Whether the node's OWN custodied wallet may SEND — `DIG_WALLET_ENABLE_LIVE_BROADCAST`
    /// (§18.12), default `false`.
    ///
    /// Read by [`Self::push_signed_bundle`], which refuses a bundle spending the node's own coins
    /// while this is `false`. Kept as an explicit flag rather than inferred from `broadcaster`
    /// being attached: that would make the custody rule a side effect of an unrelated wiring
    /// decision, and any future caller that attaches a broadcaster for another reason would
    /// silently switch the node's own money back on.
    node_custodied_spending: bool,
    /// Every BLS public key this backend has seen a NODE-CUSTODIED signer hold, accumulated as
    /// signers come and go.
    ///
    /// Needed because the default custody mode (§18.24 per-transaction re-auth) drops the signer
    /// the moment it has signed: by the time a caller pushes the bundle it just obtained from
    /// `sign_coin_spends`, [`Self::current_signer`] is `None` again and the live signer is no
    /// longer reachable. Without this memo the push guard would be looking at an empty set on
    /// exactly the path it exists to stop. Shared across `Clone`s so one memo governs the whole
    /// backend.
    ///
    /// Keyed on public keys rather than puzzle hashes so it answers the signer's own question
    /// (see [`Self::spends_node_custodied_coin`]). PUBLIC data only — never a secret key.
    custodied_public_keys: Arc<RwLock<HashSet<PublicKey>>>,
    /// The lineage source for CAT-send input resolution (parent-spend reads).
    lineage: Option<Arc<dyn LineageSource>>,
    /// The `SyncEvent` publish bus (design A.9, #205 PR4). Always present (a fresh bus with
    /// no subscribers is a harmless no-op) so `GET /events` always has somewhere to
    /// subscribe; [`Self::with_events`] lets bring-up share the SAME bus the sync loop
    /// publishes to.
    events: Arc<EventBus>,
    /// The background chain-sync supervisor's handle (§18.6, #2501), attached at bring-up
    /// ([`Self::with_sync_handle`]). It carries the one fact the wallet DB cannot express —
    /// whether a peer is attached RIGHT NOW — which the control plane composes with the DB's
    /// persisted sync state. `None` where no supervisor runs (tests, and any bring-up that
    /// disables chain sync), and that is reported as an UNOBSERVABLE peer count, never zero.
    sync_handle: Option<super::sync_supervisor::SyncHandle>,
    /// The externally-registered watch list (§18.6f, dig_ecosystem#2823), attached at bring-up
    /// ([`Self::with_watchlist`]) so the control plane can register/deregister the addresses this
    /// node follows without reaching past the backend. `None` where no registry exists (tests, and
    /// any bring-up assembling a bare backend), and a registration attempt there is refused rather
    /// than silently accepted and dropped.
    watchlist: Option<super::watchlist::WatchRegistry>,
    /// A fixed Chia peer tier standing in for the chain transport's, for tests only.
    ///
    /// The integration harness runs with the transport deliberately never built (nothing may dial
    /// mainnet), so the real tier is unobservable there and every peer count comes back `null` —
    /// and a `null == null` comparison cannot see `control.peerCounts` and
    /// `control.wallet.syncStatus` drifting onto different sources. This gives the harness a
    /// distinctive value so the two answers stay distinguishable. `None` in every shipped build:
    /// only `with_chain_peer_tier_for_tests` sets it.
    chain_peer_tier_override: Option<super::fallback::ChainPeerTier>,
    /// The connected client's per-session PUBLIC identity (#407), seeded by `login` and
    /// cleared by `logout`. Interior-mutable + shared across `Clone`s so a `login` on one
    /// dispatch is visible to subsequent reads on the same backend. `None` until a client
    /// logs in with its public puzzle hashes — reads then fall back to the node's own
    /// configured puzzle hashes (legacy), and report "not tracking" when BOTH are empty.
    /// The node NEVER holds the client's private key (#217): scoping is by public data.
    identity: Arc<RwLock<Option<SessionIdentity>>>,
    /// The node-custodied seed lifecycle (#370), attached at bring-up ([`Self::with_custody`]) so
    /// the served backend can resolve its signer from the CURRENTLY-UNLOCKED custody session at
    /// runtime (#368 runtime signer load) — not only from a signer injected once at construction.
    /// `None` on the test/simulator path (which injects a fixed signer via [`Self::with_signer`]).
    custody: Option<WalletCustody>,
    /// Serializes key-touching signing dispatch. Only the simulator/test path can attach a signer
    /// at all ([`Self::with_signer`]); this keeps two concurrent signing calls on one shared backend
    /// from interleaving over it. Reads/non-signing methods never take it.
    sign_lock: Arc<tokio::sync::Mutex<()>>,
    /// The tipping subsystem (#378), attached at bring-up ([`Self::with_tipping`]). `None` disables
    /// the `tip.*` methods (the transport reports them unavailable). The engine holds the persisted
    /// config + ledger, the owner resolver, and the tip spender.
    tipping: Option<Arc<super::tipping::TippingEngine>>,
    /// The tip-event bus WS sessions subscribe to for `{type:"tip"}` pushes (SPEC §4.8). ALWAYS
    /// present (a default empty bus is a harmless no-op) so `/ws` always has somewhere to subscribe;
    /// [`Self::with_tip_events`] shares the SAME bus the attached [`super::tipping::TippingEngine`]
    /// publishes to. DISTINCT from [`Self::events`] so tip events never leak into the Sage-parity
    /// `SyncEvent` stream.
    tip_events: Arc<super::tipping::TipEventBus>,
    /// The GLOBAL rate bound on the EXPENSIVE coinset-fallback leg of `balance_for_address`
    /// (#1957). `control.wallet.balance` is an open, unauthenticated loopback read; the local-DB
    /// fast path is cheap + legitimate and stays unbounded, but the externally-dependent coinset
    /// fallback is a cheap amplification/oracle surface, so its aggregate call rate is capped
    /// here. Shared across `Clone`s so one bucket governs the whole backend, not per-connection.
    fallback_rate: Arc<super::rate_limit::TokenBucket>,
}

/// The connected client's PUBLIC identity for a session (#407). Scoping data only — no key.
#[derive(Debug, Clone, Default)]
struct SessionIdentity {
    /// The logged-in wallet fingerprint (informational; scoping is by puzzle hash).
    #[allow(dead_code)]
    fingerprint: u32,
    /// The client's PUBLIC puzzle hashes (normalized lowercase hex, no `0x`). Reads are
    /// scoped to these; NEVER the node's own coins.
    puzzle_hashes: Vec<String>,
}

impl WalletBackend {
    /// Build a read-only backend over a DB, a fallback tier, and the wallet config. Spend
    /// methods are disabled until a signer/broadcaster are attached (see [`Self::with_signer`]).
    pub fn new(db: WalletDb, fallback: Arc<dyn ChainFallback>, config: WalletConfig) -> Self {
        Self {
            db,
            fallback,
            config,
            signer: None,
            broadcaster: None,
            pusher: None,
            node_custodied_spending: false,
            custodied_public_keys: Arc::new(RwLock::new(HashSet::new())),
            lineage: None,
            events: Arc::new(EventBus::default()),
            sync_handle: None,
            watchlist: None,
            chain_peer_tier_override: None,
            identity: Arc::new(RwLock::new(None)),
            custody: None,
            sign_lock: Arc::new(tokio::sync::Mutex::new(())),
            tipping: None,
            tip_events: Arc::new(super::tipping::TipEventBus::default()),
            fallback_rate: Arc::new(super::rate_limit::TokenBucket::new(
                DEFAULT_FALLBACK_BURST,
                DEFAULT_FALLBACK_REFILL_PER_SEC,
            )),
        }
    }

    /// Override the coinset-fallback rate bound (#1957) — primarily for tests that want a small,
    /// deterministic pool. `capacity` is the immediate burst allowance; `refill_per_sec` the
    /// sustained rate (`0.0` = a fixed, non-replenishing pool).
    #[must_use]
    pub fn with_fallback_rate_limit(mut self, capacity: f64, refill_per_sec: f64) -> Self {
        self.fallback_rate = Arc::new(super::rate_limit::TokenBucket::new(
            capacity,
            refill_per_sec,
        ));
        self
    }

    /// Attach the tipping subsystem (#378) — enables the `tip.*` methods. The engine should be
    /// constructed with the SAME [`super::tipping::TipEventBus`] passed to [`Self::with_tip_events`]
    /// so its tip pushes reach `/ws` subscribers.
    pub fn with_tipping(mut self, tipping: Arc<super::tipping::TippingEngine>) -> Self {
        self.tipping = Some(tipping);
        self
    }

    /// Share the tip-event bus the WS transport subscribes to (must be the same bus the attached
    /// [`super::tipping::TippingEngine`] publishes to).
    pub fn with_tip_events(mut self, bus: Arc<super::tipping::TipEventBus>) -> Self {
        self.tip_events = bus;
        self
    }

    /// The tipping subsystem, if attached (#378).
    pub fn tipping(&self) -> Option<&Arc<super::tipping::TippingEngine>> {
        self.tipping.as_ref()
    }

    /// The tip-event bus `/ws` subscribes to for `{type:"tip"}` pushes (SPEC §4.8).
    pub fn tip_events(&self) -> &Arc<super::tipping::TipEventBus> {
        &self.tip_events
    }

    /// Attach the node-custodied signing keys (enables spend building + signing).
    pub fn with_signer(mut self, signer: Arc<WalletSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Attach the node-custodied seed lifecycle (#370/#368). The served backend then resolves its
    /// signer from the currently-unlocked custody session at runtime, so a paired caller's
    /// `wallet.unlock` immediately enables signing/spend WITHOUT reconstructing the backend. A
    /// bring-up-injected [`Self::with_signer`] still wins when present (the simulator path).
    pub fn with_custody(mut self, custody: WalletCustody) -> Self {
        self.custody = Some(custody);
        self
    }

    /// The node-custodied seed lifecycle, if attached (#368) — used by the transport layer to
    /// dispatch the `wallet.*` custody methods to one shared custody state machine.
    pub fn custody(&self) -> Option<&WalletCustody> {
        self.custody.as_ref()
    }

    /// Attach the pusher for ALREADY-SIGNED bundles (`control.wallet.broadcast`).
    ///
    /// Attaching this does NOT let the node spend its own coins: it holds no key either way. It
    /// only gives the node a way to relay bytes a caller signed elsewhere.
    pub fn with_pusher(mut self, pusher: Arc<dyn super::chain::SignedBundlePusher>) -> Self {
        self.pusher = Some(pusher);
        self
    }

    /// Declare whether the node's OWN custodied wallet may SEND (§18.12,
    /// `DIG_WALLET_ENABLE_LIVE_BROADCAST`). Default `false`.
    ///
    /// Set from the same config flag that decides whether a broadcaster is attached, so the one
    /// question "may this node move its own money" has one answer across every path that could
    /// move it — the node's own spend methods AND the relay of an already-signed bundle.
    #[must_use]
    pub fn with_node_custodied_spending(mut self, enabled: bool) -> Self {
        self.node_custodied_spending = enabled;
        self
    }

    /// Attach the network broadcaster (enables `auto_submit` + `submit_transaction`).
    pub fn with_broadcaster(mut self, broadcaster: Arc<dyn Broadcaster>) -> Self {
        self.broadcaster = Some(broadcaster);
        self
    }

    /// Attach the lineage source used to resolve input CAT coins for `send_cat`.
    pub fn with_lineage(mut self, lineage: Arc<dyn LineageSource>) -> Self {
        self.lineage = Some(lineage);
        self
    }

    /// Share an existing [`EventBus`] (e.g. the SAME bus the sync loop publishes
    /// [`super::events::SyncEvent`]s to) instead of this backend's own default bus.
    pub fn with_events(mut self, events: Arc<EventBus>) -> Self {
        self.events = events;
        self
    }

    /// The event bus `GET /events` (SSE, [`super::transport`]) subscribes to.
    pub fn events(&self) -> &Arc<EventBus> {
        &self.events
    }

    /// Attach the running chain-sync supervisor's handle (§18.6, #2501), so the control plane
    /// can report the live sync phase without reaching past the backend for it.
    pub fn with_sync_handle(mut self, handle: super::sync_supervisor::SyncHandle) -> Self {
        self.sync_handle = Some(handle);
        self
    }

    /// Attach the externally-registered watch list (§18.6f, #2823), so the control plane can aim
    /// this node's chain subscriptions at an account it does not custody.
    pub fn with_watchlist(mut self, watchlist: super::watchlist::WatchRegistry) -> Self {
        self.watchlist = Some(watchlist);
        self
    }

    /// The attached watch list, or `None` where this backend has none.
    ///
    /// A caller MUST surface the `None` as a refusal rather than reporting a registration that
    /// went nowhere: a client told its account is being followed when nothing is watching it reads
    /// a balance of zero as the truth.
    pub fn watchlist(&self) -> Option<&super::watchlist::WatchRegistry> {
        self.watchlist.as_ref()
    }

    /// Every coin currently held out of selection, of BOTH phases, and the clock that was read.
    ///
    /// Serves `control.wallet.reservations.held`. The clock is returned alongside the rows because
    /// the caller does not supply one: a caller-supplied `now` would be a lapse oracle, since a
    /// far-future value makes every live hold read as expired. Reporting the node's own instant
    /// lets a client SEE skew instead of imposing it.
    ///
    /// A failure propagates. It is never flattened into an empty list: "nothing is held" permits a
    /// caller to spend and "I cannot tell you" must stop it, and collapsing the two restores the
    /// double-select the set exists to prevent.
    pub async fn reservations_held(&self) -> sqlx::Result<(Vec<ReservedCoinRow>, i64)> {
        let now_ms = super::custody::now_ms() as i64;
        // Retire what has lapsed before reporting, so a hold that is already over is never shown
        // to a caller as something to wait for.
        self.db.prune_reservations(now_ms).await?;
        Ok((self.db.held_reservations(now_ms).await?, now_ms))
    }

    /// Atomically hold `coin_ids` against further selection — all of them or none.
    ///
    /// Serves `control.wallet.reservations.reserve`. §908: bookkeeping only. A coin id is a public
    /// chain fact; this holds no key, signs nothing and authorizes nothing.
    ///
    /// The lifetime is clamped by [`WalletDb::reserve_client_coins`] and the APPLIED one is
    /// returned, because a caller told its own requested figure would wait on a schedule this node
    /// does not keep.
    pub async fn reserve_coins(
        &self,
        coin_ids: &[String],
        ttl_secs: Option<u64>,
    ) -> std::result::Result<ClientReservation, ReserveClientCoinsError> {
        let now_ms = super::custody::now_ms() as i64;
        self.db.prune_reservations(now_ms).await?;
        // `saturating_mul` rather than a cast: a caller naming a TTL near `u64::MAX` must not wrap
        // into a negative lifetime, which would produce a hold already expired at birth and read
        // to that caller as a grant that silently vanished.
        let ttl_ms = ttl_secs.map(|s| (s.min(i64::MAX as u64 / 1000) as i64).saturating_mul(1000));
        self.db.reserve_client_coins(coin_ids, ttl_ms, now_ms).await
    }

    /// Free a hold ahead of its lifetime, returning the coins released.
    ///
    /// Serves `control.wallet.reservations.release`. An unknown handle frees nothing and is NOT an
    /// error — a caller releasing on confirmation cannot know whether the TTL got there first, and
    /// making the ordinary outcome an error teaches callers to stop checking the result, which is
    /// how a release path quietly stops being called.
    pub async fn release_reservation(&self, reservation_id: &str) -> sqlx::Result<Vec<String>> {
        self.db.release_client_reservation(reservation_id).await
    }

    /// Enrol `keys` to be followed.
    ///
    /// The single door onto [`super::watchlist::WatchRegistry::watch`], and now a thin one: it
    /// registers, and nothing else. Enrolment WIDENS the set of addresses reads treat as
    /// replica-backed, and the replica's completed catch-up covered the OLD set — but that is no
    /// longer this method's problem to remember. The completed catch-up records the set it actually
    /// ran over ([`super::coverage`]), and [`Self::replica_is_authoritative`] compares it against
    /// the set this node follows RIGHT NOW, so a widening invalidates coverage by arithmetic rather
    /// than by a second write landing in the right order (dig_ecosystem#2871).
    ///
    /// That matters because ordering was never achievable here. Registration persists before any
    /// follow-up could run, so a failed or interrupted invalidation left the widened set latched —
    /// and `watch` is idempotent, so the client's retry enrolled nothing and would have invalidated
    /// nothing. Deleting the second write deletes the window.
    ///
    /// Returns how many keys were newly enrolled, or `None` where no registry is attached — which
    /// a caller MUST surface as a refusal rather than as a registration that went nowhere.
    pub fn watch_keys(&self, keys: &[PublicKey]) -> Option<usize> {
        let registry = self.watchlist.as_ref()?;
        let added = registry.watch(keys);
        if added > 0 {
            tracing::info!(
                added,
                concat!(
                    "wallet watch: newly enrolled keys widened the followed set; ",
                    "the replica answers for none of it until a catch-up covers the widened set",
                )
            );
        }
        Some(added)
    }

    /// The puzzle-hash set this backend FOLLOWS right now — its custody's addresses plus every
    /// externally enrolled key's.
    ///
    /// Delegates to [`super::sync_supervisor::followed_puzzle_hashes`], the SAME union the
    /// supervisor subscribes, so "did the sync cover what we follow?" is asked about one set rather
    /// than two spellings of it.
    fn followed_set(&self) -> CoveredSet {
        CoveredSet::from_hashes(&super::sync_supervisor::followed_puzzle_hashes(
            self.custody.as_ref(),
            self.watchlist.as_ref(),
        ))
    }

    /// May the local replica answer for money?
    ///
    /// TWO facts, not one. `initial_sync_complete` says a catch-up FINISHED; the recorded covered
    /// set says which addresses it finished OVER. Routing on the flag alone is what answered a
    /// funded, newly-enrolled address `balance: 0, synced: true, source: "db"` — the DB was queried
    /// for a scope it had never been asked to follow (dig_ecosystem#2871).
    ///
    /// Asked as CONTAINMENT: a widened followed set is no longer covered and every read falls to
    /// the chain oracle until a catch-up covers it, while a NARROWED one (an `unwatch`) stays
    /// covered, because a sync over the wider set genuinely covered what remains. An absent
    /// recording — a pre-#2871 replica, or the oracle refresh declining to claim coverage — covers
    /// nothing.
    ///
    /// Both money reads ([`Self::balance_for_address`], [`Self::coins_for_address`]) call this and
    /// nothing else, so the two cannot come to differ about when the replica is trusted.
    async fn replica_is_authoritative(&self) -> sqlx::Result<bool> {
        self.replica_covers(&self.followed_set()).await
    }

    /// May the local replica answer for `scope` — the puzzle-hash set ONE read is scoped to?
    ///
    /// The containment question [`Self::replica_is_authoritative`] asks, with the scope made an
    /// argument, because the ecosystem has two of them and they are not the same question.
    /// An ADDRESS-scoped read is answerable when the catch-up covered everything this node
    /// follows; an IDENTITY-scoped read is answerable when it covered the puzzle hashes the
    /// CONNECTED CLIENT supplied, which arrive per-connection and need not be followed at all.
    ///
    /// Routing the identity-scoped reads through the followed set would be vacuous rather than
    /// wrong-in-a-visible-way: a node with no custody and no watchlist follows nothing, every
    /// recording covers the empty set, and the uncovered client would be served a synced zero
    /// exactly as before (dig_ecosystem#2878).
    ///
    /// An absent recording covers nothing, so a replica that latched the flag without recording
    /// what it ran over fails closed for every scope.
    async fn replica_covers(&self, scope: &CoveredSet) -> sqlx::Result<bool> {
        let state = self.db.sync_state().await?;
        Ok(state.initial_sync_complete
            && state.covered.is_some_and(|covered| covered.covers(scope)))
    }

    /// May the replica answer for the CONNECTED CLIENT's identity?
    ///
    /// The gate for every identity-scoped Sage-parity read. Phrased over
    /// [`Self::scoped_identity`] so the set that is checked is byte-for-byte the set that is
    /// queried — a gate asked about a different spelling of the scope is not a gate.
    async fn replica_covers_client_scope(&self, identity: &[String]) -> sqlx::Result<bool> {
        self.replica_covers(&CoveredSet::from_hex(identity)).await
    }

    /// Does `phs` cover every externally enrolled address — so a sync over `phs` alone may declare
    /// the whole replica authoritative?
    ///
    /// A registry that is absent or empty is trivially covered: there is no enrolled address to
    /// leave behind. Comparison is on normalised puzzle hashes, the same spelling
    /// [`Self::watchlist_follows`] compares on, so the two cannot disagree about the same key.
    fn watchlist_is_covered_by(&self, phs: &[String]) -> bool {
        let Some(registry) = self.watchlist.as_ref() else {
            return true;
        };
        let covered: HashSet<String> = phs.iter().map(|p| normalize_ph(p)).collect();
        registry.registered().iter().all(|pk| {
            covered.contains(&normalize_ph(&hex::encode(
                super::sync_supervisor::puzzle_hash_for(pk),
            )))
        })
    }

    /// Does this replica FOLLOW `puzzle_hash` because an enrolled key controls it?
    ///
    /// This is the second half of the "is this address ours" question, and without it the first
    /// half answers for both. `derivation_exists` looks in the `derivations` table, which only
    /// this node's own custody writes; an externally enrolled key
    /// ([`super::watchlist::WatchRegistry`]) joins the subscription set and its coins ARE synced
    /// into the replica, but it never becomes a derivation row. So a node that had enrolled the
    /// user's account, caught up, and was tracking the chain still routed every balance read to
    /// the third-party oracle — the replica held the coins and the router could not see that it
    /// did (dig_ecosystem#2866).
    ///
    /// FOLLOWED, not merely KNOWN. The predicate must stay a membership test over the registry:
    /// answering `true` for an arbitrary address would route a puzzle hash this replica does not
    /// subscribe to at the local DB, which holds no coins for it, and report a funded wallet as
    /// EMPTY. That is the falsehood [`super::sync::initial_sync`]'s `NoPuzzleHashes` refusal
    /// exists to prevent, arriving through a different door.
    ///
    /// The mapping comes from [`super::sync_supervisor::puzzle_hash_for`] — the SAME function the
    /// supervisor uses to build the subscription set, so the router and the subscriber cannot
    /// disagree about which address a key controls.
    fn watchlist_follows(&self, puzzle_hash: &str) -> bool {
        let Some(registry) = self.watchlist.as_ref() else {
            return false;
        };
        registry.registered().iter().any(|pk| {
            normalize_ph(&hex::encode(super::sync_supervisor::puzzle_hash_for(pk))) == puzzle_hash
        })
    }

    /// Report a FIXED Chia peer tier instead of the chain transport's — TESTS ONLY.
    ///
    /// The counterpart of [`super::sync_supervisor::SyncHandle::detached_for_tests`], and for the
    /// same reason: the harness must be able to give these counts distinctive values without
    /// anything dialling mainnet to earn them.
    #[doc(hidden)]
    pub fn with_chain_peer_tier_for_tests(mut self, tier: super::fallback::ChainPeerTier) -> Self {
        self.chain_peer_tier_override = Some(tier);
        self
    }

    /// The node's OWN Chia peer tier — peers held, and the peak they announced.
    ///
    /// A local read of the transport's cached state: it makes no oracle call, so it opens none of
    /// the egress this file refuses elsewhere, and it is cheap enough to take on an ordinary read
    /// path. It is the second opinion every freshness claim needs, because the replica's own peak
    /// cannot say how far behind the replica is.
    async fn chain_peer_tier(&self) -> super::fallback::ChainPeerTier {
        match self.chain_peer_tier_override {
            Some(fixed) => fixed,
            None => self.fallback.peer_tier().await,
        }
    }

    /// Whether a figure taken from the replica AT `peak_height` may be reported as CURRENT.
    ///
    /// `db_synced` — which chose the replica in the first place — cannot answer this. It is
    /// `initial_sync_complete`, which records that a catch-up once FINISHED and is cleared only by
    /// a backwards chain move; a replica hundreds of blocks behind still satisfies it. Reporting
    /// `synced: true` on that basis told a client a stale balance was settled, which is the
    /// money-adjacent falsehood dig_ecosystem#2869 exists to remove.
    ///
    /// It reuses [`super::sync_supervisor::is_following`] — the SAME predicate
    /// `control.wallet.syncStatus` reports its phase from — so a client cannot be told `synced` by
    /// one endpoint and `syncing` by the other about the same moment.
    ///
    /// That agreement is STRUCTURAL rather than asserted, and it was not always: this method is
    /// now the only way any read produces `synced: true`. Every other site writes the literal
    /// `false`, on a fallback-tier answer, where a third party's height says nothing about the
    /// replica. `chain_peak` used to be the exception — it computed its flag from
    /// `db.is_synced()` directly and so could, and on a live node did, report `synced: true`
    /// about the same replica this method was calling stale (dig-node#293).
    ///
    /// It narrows that predicate on BOTH of its unobservable arms, and only here. `is_following`
    /// answers `true` whenever EITHER height is missing, because on a status endpoint an absent
    /// measurement is not an accusation against the replica. On a money read it is the opposite:
    /// currency is a claim, and nothing that was never measured can establish one. Either arm left
    /// unnarrowed leaves `synced: true` resting on the latched `initial_sync_complete` this method
    /// exists to stop trusting.
    ///
    /// - **No PEER height** — there is no second opinion to compare the replica against.
    /// - **No REPLICA height** — there is no figure to compare, and `synced: true` would then be
    ///   paired with `peak_height: null`, telling a client a reading is current while refusing to
    ///   say what it is a reading OF. That arm is production-reachable, not hypothetical:
    ///   `refresh_tracked_coins` latches the replica authoritative without ever writing a peak.
    ///   `chain_peak` escapes it only by construction (it calls this inside `if let Some(peak)`);
    ///   the balance and coin reads pass their `Option` straight through, so the arm landed on
    ///   exactly the money reads (dig-node#293).
    ///
    /// Either way the figure is still SERVED, with whatever `peak_height` is actually known,
    /// labelled stale — never withheld.
    ///
    /// `is_following` itself is deliberately left ALONE. Its permissive `_ => true` is correct for
    /// the sync-phase reporting it was written for, where an unmeasured tier must not be spent as
    /// evidence against a replica; narrowing it there would change a phase machine owned by another
    /// family. The narrowing is a property of the MONEY read, so it lives at this call site.
    ///
    /// That placement has a LIMIT, and it is stated here rather than left to be rediscovered:
    /// this method is the single gate for every read served by [`WalletBackend`] — each one either
    /// passes through here or writes the literal `false` — but it is NOT the only producer of a
    /// `synced` claim in the crate. [`super::sync_supervisor::SyncHandle::status`] reaches
    /// `SyncPhase::Synced` through its own `is_following` call and pairs it with the replica's raw
    /// `peak_height`, so `control.wallet.sync-status` can still emit
    /// `{phase: "synced", peak_height: null}` — the exact pairing this gate abolishes on the money
    /// reads. That path is deliberately out of scope: it is a status endpoint rather than a
    /// currency claim, and the phase machine belongs to another family (dig_ecosystem#2761).
    ///
    /// The asymmetry worth carrying into that work: `is_following`'s own doc justifies its
    /// permissive arm ENTIRELY in terms of an unmeasured PEER tier, and offers no justification at
    /// all for the unmeasured-REPLICA arm. Those are different things. An absent peer height is a
    /// missing second opinion, which is fairly read as no accusation; an absent replica height is
    /// the subject of the claim having no measurement whatsoever, which supports no verdict in
    /// either direction.
    async fn replica_answer_is_current(&self, peak_height: Option<u32>) -> bool {
        let Some(replica_peak) = peak_height else {
            return false;
        };
        let Some(peer_peak) = self.chain_peer_tier().await.peak_height else {
            return false;
        };
        super::sync_supervisor::is_following(Some(replica_peak), Some(peer_peak))
    }

    /// The chain-sync supervisor's handle, if one is running.
    pub fn sync_handle(&self) -> Option<&super::sync_supervisor::SyncHandle> {
        self.sync_handle.as_ref()
    }

    /// The wallet's background chain-sync status (§18.6, #2501) — **the one source** for both
    /// the sync phase and the live Chia peer count.
    ///
    /// `control.wallet.syncStatus` and `control.peerCounts` both report that peer count, and
    /// serving them from one place is what makes it impossible for the two to disagree.
    ///
    /// The peak reported is the REPLICA's own
    /// ([`super::db::WalletDb::sync_state`]) and is read directly from the DB. It must never come
    /// from [`Self::chain_peak`]: that method falls back to a coinset ORACLE behind the
    /// `fallback_rate` limiter, so routing this unauthenticated loopback read through it would
    /// both answer the wallet's own progress with a third party's height and open a second
    /// unbounded egress path (dig_ecosystem#1957) that also discloses `{IP, timestamp, coin id}`
    /// to that third party.
    ///
    /// Drop the chain-derived cache and force a re-sync from chain (dig-node#384).
    ///
    /// A thin pass-through to [`WalletDb::reset_chain_cache`], which holds the whole contract:
    /// the authoritative flag is cleared in the same transaction as the coins, an in-flight spend
    /// refuses, and no key material is reachable. Exposed here because the control plane holds a
    /// backend, not a database.
    pub async fn reset_coin_db(
        &self,
        now_ms: i64,
    ) -> sqlx::Result<std::result::Result<super::db::ResetReport, super::db::ResetRefusal>> {
        self.db.reset_chain_cache(now_ms).await
    }

    /// With no supervisor the peer count is reported UNOBSERVABLE (`None`), never zero — zero
    /// would claim an observation nobody made.
    pub async fn wallet_sync_status(
        &self,
    ) -> sqlx::Result<super::sync_supervisor::WalletSyncStatus> {
        // The node's own Chia peer tier (dig_ecosystem#2806) comes from the chain transport, not
        // from the supervisor: the transport holds the pool that SERVES chain reads, whereas the
        // supervisor holds at most one subscription session to write the replica. Reporting the
        // supervisor's session as the peer count is what made a node holding five peers say it
        // held one.
        //
        // This is a local read of the transport's own state plus a cached peak the peers pushed;
        // it makes no oracle call, so it does not open the egress path this method's doc above
        // refuses for the peak.
        let tier = self.chain_peer_tier().await;
        match &self.sync_handle {
            Some(h) => h.status(&self.db, tier).await,
            None => super::sync_supervisor::status_without_supervisor(&self.db, tier).await,
        }
    }

    /// The exact method set this PR serves (the core READ surface). Used by the
    /// conformance test to assert the dispatched set matches the design's MUST-tier
    /// read methods, and by callers to pre-check support.
    pub const SUPPORTED_METHODS: &'static [&'static str] = &[
        "login",
        "logout",
        "get_version",
        "get_sync_status",
        "check_address",
        "get_derivations",
        "get_are_coins_spendable",
        "get_spendable_coin_count",
        "get_coins",
        "get_coins_by_ids",
        "get_cats",
        "get_all_cats",
        "get_token",
        "get_dids",
        "get_nfts",
        "get_nft",
        "get_nft_data",
        "get_nft_collections",
        "get_nft_collection",
        "get_transactions",
        "get_transaction",
        "get_pending_transactions",
        "is_asset_owned",
        "get_key",
        "get_keys",
        // #216 send/spend group.
        "send_xch",
        "bulk_send_xch",
        "send_cat",
        "bulk_send_cat",
        "combine",
        "split",
        "multi_send",
        "sign_coin_spends",
        "view_coin_spends",
        "submit_transaction",
        // #218 offer suite.
        "make_offer",
        "take_offer",
        "view_offer",
        "combine_offers",
        "get_offers",
        "get_offer",
        "cancel_offer",
        // #218 DID/NFT mint + transfer.
        "create_did",
        "bulk_mint_nfts",
        "transfer_nfts",
        "transfer_dids",
        // #205 PR4: options (exercise_options is served but returns a documented error —
        // see `sage::options` module docs).
        "get_options",
        "get_option",
        "mint_option",
        "transfer_options",
        "exercise_options",
        // #205 PR4: actions.
        "resync_cat",
        "update_cat",
        "update_did",
        "update_option",
        "update_nft",
        "update_nft_collection",
        "redownload_nft",
        "increase_derivation_index",
        // #205 PR4: themes.
        "get_user_themes",
        "get_user_theme",
        "save_user_theme",
        "delete_user_theme",
        // #205 PR4: network / peers / settings.
        "get_peers",
        "add_peer",
        "remove_peer",
        "set_discover_peers",
        "set_target_peers",
        "set_network",
        "set_network_override",
        "get_networks",
        "get_network",
        "set_delta_sync",
        "set_delta_sync_override",
        "set_change_address",
    ];

    /// Whether `method` is served by this backend.
    pub fn supports(method: &str) -> bool {
        Self::SUPPORTED_METHODS.contains(&method)
    }

    /// The spendable **$DIG** at this node's own operator puzzle hash, in DIG CAT base units.
    ///
    /// `None` when the balance could not be read — an unreachable chain source, a replica that is
    /// not authoritative for this address, a figure too large for a `u64`. `None` is **not zero**:
    /// §25's bond surface reports an uncovered bond as `deferred{balance_unreadable}` on `None` and
    /// as `unfunded` on `Some(0)`, and those are opposite claims — the first says the node does not
    /// know, the second raises an out-of-funds alarm. Substituting zero for an unreadable balance is
    /// the dig-app#300 conflation.
    ///
    /// Takes the puzzle hash rather than an address so no caller has to spell an address, pick a
    /// prefix, or name the asset: the encoding and the canonical `$DIG` asset id both stay inside
    /// this crate, where the one definition of each already lives. A caller that assembled its own
    /// address string could read the right amount of the wrong asset at the wrong network's prefix,
    /// and every one of those returns a confident number.
    ///
    /// **Staleness is NOT covered by `None`, and a caller must not read it as freshness.** Being
    /// authoritative for an address and being current with the chain are independent questions, and
    /// only the first can fail the read: a replica that is in scope but behind answers `Ok` with
    /// `synced: false`, so this returns `Some` of a figure that may lag the chain. A caller that
    /// needs currency must ask for it — `balance_for_address` returns `source`, `synced` and
    /// `peak_height`, and this narrowing keeps only `balance`. Discriminating on `synced` alone
    /// would be wrong in the other direction, because the fallback arm hard-codes it false for
    /// answers that are perfectly good.
    ///
    /// This is a READ. It confers no custody and touches no key: the puzzle hash is a public value.
    pub async fn dig_balance_base_units(&self, owner_puzzle_hash: Bytes32) -> Option<u64> {
        let address = self.address_of(&hex::encode(owner_puzzle_hash));
        let read = self
            .balance_for_address(&address, BalanceAsset::DIG)
            .await
            .ok()?;
        // Narrowed rather than saturated. A saturating cast would report a balance above `u64::MAX`
        // as exactly `u64::MAX` — the largest possible confident wrong number on a funding decision.
        u64::try_from(read.balance).ok()
    }

    // ---- address helpers --------------------------------------------------

    /// The bech32m human-readable prefix this backend's network uses -- `xch` on mainnet, `txch`
    /// on testnet11.
    ///
    /// Exposed so a caller encoding an address OUTSIDE this backend encodes it for the SAME network
    /// the backend reads coins on. A second source for the prefix is how a node ends up rendering a
    /// mainnet address beside a testnet balance, which reads as one wallet and is two.
    pub fn address_prefix(&self) -> &str {
        &self.config.address_prefix
    }

    fn address_of(&self, puzzle_hash_hex: &str) -> String {
        encode_address(puzzle_hash_hex, &self.config.address_prefix)
            .unwrap_or_else(|| puzzle_hash_hex.to_string())
    }

    fn burn_address(&self) -> String {
        encode_address(&"00".repeat(32), &self.config.address_prefix).unwrap_or_default()
    }

    // ---- coin → wire mapping ---------------------------------------------

    fn coin_row_to_record(&self, c: &CoinRow) -> CoinRecord {
        CoinRecord {
            coin_id: c.coin_id.clone(),
            address: self.address_of(&c.puzzle_hash),
            amount: Amount::u128(c.amount.parse::<u128>().unwrap_or(0)),
            transaction_id: None,
            offer_id: None,
            clawback_timestamp: None,
            created_height: c.created_height.map(|h| h as u32),
            spent_height: c.spent_height.map(|h| h as u32),
            spent_timestamp: c.spent_timestamp.map(|t| t as u64),
            created_timestamp: c.created_timestamp.map(|t| t as u64),
        }
    }

    fn fallback_coin_to_record(&self, c: &FallbackCoin) -> CoinRecord {
        CoinRecord {
            coin_id: c.coin_id.clone(),
            address: self.address_of(&c.puzzle_hash),
            amount: Amount::u64(c.amount),
            transaction_id: None,
            offer_id: None,
            clawback_timestamp: None,
            created_height: c.created_height,
            spent_height: c.spent_height,
            spent_timestamp: c.spent_timestamp,
            created_timestamp: c.created_timestamp,
        }
    }

    /// Whether the initial subscription catch-up is complete (the routing gate, B.6).
    async fn synced(&self) -> Result<bool> {
        Ok(self.db.is_synced().await?)
    }

    /// The chain-fallback coins of ONE asset held at `puzzle_hashes` — the fallback tier's
    /// answer, scoped to the asset that was asked for.
    ///
    /// Shared verbatim by [`Self::balance_for_address`] and [`Self::coins_for_address`], which are
    /// the same read reduced and unreduced. It lives here because the scoping is the subtle part:
    /// duplicating it is how one copy came to be missing (dig_ecosystem#2879).
    ///
    /// # A hint is not an asset
    ///
    /// XCH coins sit AT the puzzle hash, so that read is asset-scoped by construction — nothing
    /// but native XCH can be there, since a CAT lives at the outer hash currying its TAIL.
    ///
    /// CAT coins are HINTED to the puzzle hash, and `coin_records_by_hints` takes no asset
    /// argument: it answers with EVERY coin hinted to the address — any CAT, and any plain XCH
    /// coin whose spend carried a hint memo. Summing that answer as one asset reported a `$DIG`
    /// balance nobody held, and reported it at `$DIG`'s scale rather than the coin's own: one
    /// hinted XCH coin of 10^8 mojos (`0.0001 XCH`) rendered as `100000 $DIG`.
    ///
    /// So a hint read is FILTERED to the coins that live where this asset's coins live. Filtering
    /// too hard is the same lie mirrored — a real `$DIG` holder shown a zero — so the filter keys
    /// on the canonical CAT puzzle hash for the asset ([`BalanceAsset::cat_coin_puzzle_hash`])
    /// rather than on anything heuristic.
    async fn asset_scoped_fallback_coins(
        &self,
        asset: BalanceAsset,
        puzzle_hashes: &[String],
    ) -> Result<Vec<super::fallback::FallbackCoin>> {
        let Some(_) = asset.cat_asset_id() else {
            return self
                .fallback
                .coin_records_by_puzzle_hashes(puzzle_hashes)
                .await;
        };
        // Every puzzle hash the caller asked about, rendered as the place this asset's coins for
        // it would sit. A coin outside this set is hinted to us but belongs to something else.
        let mut asset_hashes = HashSet::with_capacity(puzzle_hashes.len());
        for ph in puzzle_hashes {
            if let Some(h) = asset.cat_coin_puzzle_hash(ph)? {
                asset_hashes.insert(h);
            }
        }
        let hinted = self.fallback.coin_records_by_hints(puzzle_hashes).await?;
        Ok(hinted
            .into_iter()
            .filter(|c| asset_hashes.contains(&normalize_ph(&c.puzzle_hash)))
            .collect())
    }

    /// The confirmed + pending balance held at ONE address, for XCH or $DIG (#1851).
    ///
    /// A READ-ONLY chain view — it needs only a public address, never a seed or signing key,
    /// so it carries zero custody risk and answers the `control.wallet.balance` control read.
    /// It reuses the EXISTING B.6 routing ([`routing::route`]):
    ///
    /// - **Wallet-owned address, DB synced** → the local DB is authoritative:
    ///   [`db::WalletDb::balance_scoped`] (confirmed) + [`db::WalletDb::pending_scoped`]
    ///   (unconfirmed); `source = "db"`, `synced = true`, `peak_height` = the node's own peak.
    /// - **Otherwise** → the fallback (coinset) tier answers; `source = "fallback"`,
    ///   `synced = false`, `peak_height = null`. If no LIVE fallback is attached, the read
    ///   cannot honestly answer, so it returns a DISTINCT error rather than a fabricated `0`:
    ///   [`BalanceError::NotSynced`] for the wallet's own address (the DB would answer once
    ///   synced), [`BalanceError::NoChainSource`] for an arbitrary address (only a chain
    ///   source could).
    ///
    /// **Every reported state field describes the tier that answered** (#2233). Reading the
    /// DB's `synced` / `peak_height` on a coinset-served answer would describe the local
    /// replica rather than the figure returned — so once a sync loop flips that flag, a
    /// third-party oracle read would report itself as a synced local read. Those two fields
    /// are therefore produced INSIDE the tier arms, never before the decision.
    pub async fn balance_for_address(
        &self,
        address: &str,
        asset: BalanceAsset,
    ) -> std::result::Result<WalletBalanceResult, BalanceError> {
        let puzzle_hash =
            normalize_ph(&decode_address(address).ok_or(BalanceError::InvalidAddress)?);
        let asset_id = asset.asset_id_hex();

        let read_err = |e: Error| BalanceError::ReadFailed(e.to_string());
        // NOT `is_synced()`. The flag alone says a catch-up finished, never over WHICH addresses;
        // routing on it answered a newly-enrolled funded address a dated zero (dig_ecosystem#2871).
        let db_synced = self
            .replica_is_authoritative()
            .await
            .map_err(|e| read_err(e.into()))?;
        // An address is IN SCOPE when this replica follows it: either this node derived it, or an
        // enrolled key controls it. Enrolment never writes a derivation row, so the first test
        // alone was false forever for every registered address (dig_ecosystem#2866).
        let scoped = self
            .db
            .derivation_exists(&puzzle_hash)
            .await
            .map_err(|e| read_err(e.into()))?
            || self.watchlist_follows(&puzzle_hash);

        let source = routing::route(db_synced, scoped);
        // Disclose the tier in the node log as well as on the wire, so an operator reading
        // `dig-node.jsonl` can tell a local-replica answer from a third-party oracle call.
        //
        // Split by level deliberately. `dig-logging`'s baked-in default is `info`
        // (dig-logging `filter.rs:21`), and a stock install sets none of the overrides -- so a
        // `debug!` here is INVISIBLE on every default node, which would make SPEC §18.7b's
        // "dig-node.jsonl records the same tier the wire reports" false in the field and would
        // let an acceptance run reading the log mistake silence for "no fallback occurred"
        // (dig-node#189 review).
        //
        // FALLBACK is `info`: it is the exceptional path, it means this read was disclosed to a
        // third-party oracle, and it is the evidence #2232's acceptance depends on. DB is `debug`:
        // once sync works it is the ordinary path, and logging every local read at `info` would
        // amplify an OPEN unauthenticated loopback endpoint into a log-volume lever.
        match source {
            Source::Db => tracing::debug!(tier = source.as_wire(), "wallet balance read routed"),
            Source::Fallback => tracing::info!(
                tier = source.as_wire(),
                "wallet balance read routed to the third-party chain oracle"
            ),
        }

        match source {
            Source::Db => {
                let scope = [puzzle_hash];
                let balance = self
                    .db
                    .balance_scoped(asset_id.as_deref(), &scope)
                    .await
                    .map_err(|e| read_err(e.into()))?;
                let pending = self
                    .db
                    .pending_scoped(asset_id.as_deref(), &scope)
                    .await
                    .map_err(|e| read_err(e.into()))?;
                // The peak is read HERE, inside the arm, because it describes the replica
                // this answer came from — it is not context for an answer taken elsewhere.
                let peak_height = self
                    .db
                    .sync_state()
                    .await
                    .map_err(|e| read_err(e.into()))?
                    .peak_height;
                Ok(WalletBalanceResult {
                    balance,
                    pending,
                    source,
                    // Measured, not assumed: this arm reports what the replica HOLDS, and whether
                    // that is current is a different question from whether the replica was
                    // eligible to answer (dig_ecosystem#2869).
                    synced: self.replica_answer_is_current(peak_height).await,
                    peak_height,
                })
            }
            Source::Fallback => {
                // A fallback read must consult the chain; without a live source it cannot
                // honestly answer. Distinguish "own address, still syncing" from "arbitrary
                // address, no chain source" so the caller sees WHY (never a fabricated 0).
                if !self.fallback.is_live() {
                    return Err(if scoped {
                        BalanceError::NotSynced
                    } else {
                        BalanceError::NoChainSource
                    });
                }
                // Defense-in-depth (#1957): the coinset fallback is the ONLY expensive,
                // externally-dependent leg of this open read. Bound its aggregate call rate so an
                // unauthenticated loopback caller cannot sweep arbitrary addresses to amplify load
                // on / oracle the fallback. The cheap DB fast path above is never gated.
                if !self.fallback_rate.try_acquire() {
                    return Err(BalanceError::RateLimited);
                }
                let phs = [puzzle_hash];
                let coins = self
                    .asset_scoped_fallback_coins(asset, &phs)
                    .await
                    .map_err(read_err)?;
                let (mut balance, mut pending) = (0u128, 0u128);
                for c in &coins {
                    if c.spent_height.is_some() {
                        continue;
                    }
                    if c.created_height.is_some() {
                        balance += u128::from(c.amount);
                    } else {
                        pending += u128::from(c.amount);
                    }
                }
                Ok(WalletBalanceResult {
                    balance,
                    pending,
                    source,
                    // The DB neither produced this figure nor bounds its freshness, so its
                    // flag and its peak say nothing about it. `false` / `null` is the truth
                    // about a coinset-served answer, whatever the local replica's state.
                    synced: false,
                    peak_height: None,
                })
            }
        }
    }

    /// The UNSPENT coins held at ONE address for XCH or $DIG (dig_ecosystem#2376).
    ///
    /// The read a caller building a spend needs, and the exact sibling of
    /// [`balance_for_address`](Self::balance_for_address) — a balance is this read reduced to a
    /// sum, so it takes the same params and routes through the same B.6 tiers.
    ///
    /// # An empty list is an ANSWER
    ///
    /// `coins: []` means a chain WAS consulted and this address holds nothing. Every way of not
    /// reaching a chain is a [`BalanceError`] instead. Degrading an unreachable chain into an empty
    /// list would tell a person holding funds that they hold none, and a spend built on that answer
    /// refuses with a shortfall that is not true.
    ///
    /// # "Unspent", not "confirmed"
    ///
    /// Coins seen only in the mempool are INCLUDED, with `created_height: None`. The caller decides
    /// whether an unconfirmed coin is spendable for its purpose; the node does not decide for it by
    /// hiding one.
    pub async fn coins_for_address(
        &self,
        address: &str,
        asset: BalanceAsset,
        after_coin_id: Option<&str>,
        limit: u32,
    ) -> std::result::Result<WalletCoinsResult, BalanceError> {
        let puzzle_hash =
            normalize_ph(&decode_address(address).ok_or(BalanceError::InvalidAddress)?);
        let asset_id = asset.asset_id_hex();

        let read_err = |e: Error| BalanceError::ReadFailed(e.to_string());
        // NOT `is_synced()`. The flag alone says a catch-up finished, never over WHICH addresses;
        // routing on it answered a newly-enrolled funded address a dated zero (dig_ecosystem#2871).
        let db_synced = self
            .replica_is_authoritative()
            .await
            .map_err(|e| read_err(e.into()))?;
        // An address is IN SCOPE when this replica follows it: either this node derived it, or an
        // enrolled key controls it. Enrolment never writes a derivation row, so the first test
        // alone was false forever for every registered address (dig_ecosystem#2866).
        let scoped = self
            .db
            .derivation_exists(&puzzle_hash)
            .await
            .map_err(|e| read_err(e.into()))?
            || self.watchlist_follows(&puzzle_hash);

        let source = routing::route(db_synced, scoped);
        match source {
            Source::Db => tracing::debug!(tier = source.as_wire(), "wallet coin read routed"),
            Source::Fallback => tracing::info!(
                tier = source.as_wire(),
                "wallet coin read routed to the third-party chain oracle"
            ),
        }

        match source {
            Source::Db => {
                let scope = [puzzle_hash];
                // Scope, asset, unspent and the page bound are ONE query. Paging a broader read
                // and filtering afterwards would cut the page before the filter, so a page would
                // arrive short and `complete` would be computed from a count that no longer
                // describes what remains.
                let rows = self
                    .db
                    .unspent_coins_page(asset_id.as_deref(), &scope, after_coin_id, limit)
                    .await
                    .map_err(|e| read_err(e.into()))?;
                let peak_height = self
                    .db
                    .sync_state()
                    .await
                    .map_err(|e| read_err(e.into()))?
                    .peak_height;
                let page_size = limit as usize;
                // The query returned up to one row PAST the page; its existence is what says more
                // remain, and it is dropped rather than served.
                let complete = rows.len() <= page_size;
                let coins = rows
                    .iter()
                    .take(page_size)
                    .map(coin_from_row)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(read_err)?;
                Ok(WalletCoinsResult {
                    cursor: coins.last().map(|c| c.coin_id.clone()),
                    complete,
                    coins,
                    source,
                    // The same measurement as the balance read's: this is that answer unreduced,
                    // and the caller building a spend on it is the one who can least afford to be
                    // told a stale coin set is current.
                    synced: self.replica_answer_is_current(peak_height).await,
                    peak_height,
                })
            }
            Source::Fallback => {
                // Identical routing to the balance read: no live source means the answer is
                // UNKNOWN, and WHICH unknown it is tells the caller why (#1851).
                if !self.fallback.is_live() {
                    return Err(if scoped {
                        BalanceError::NotSynced
                    } else {
                        BalanceError::NoChainSource
                    });
                }
                if !self.fallback_rate.try_acquire() {
                    return Err(BalanceError::RateLimited);
                }
                let phs = [puzzle_hash];
                let mut unspent: Vec<WalletCoin> = self
                    .asset_scoped_fallback_coins(asset, &phs)
                    .await
                    .map_err(read_err)?
                    .iter()
                    .filter(|c| c.spent_height.is_none())
                    .map(coin_from_fallback)
                    .collect();
                // Sorted HERE rather than trusted from the source, for the reason
                // `coins_by_parent` records: the tier underneath merges peer and coinset answers
                // and promises no order at all, and an order that varies between pages loses rows.
                unspent.sort_by(|a, b| a.coin_id.cmp(&b.coin_id));
                let remaining: Vec<WalletCoin> = match after_coin_id {
                    Some(cursor) => unspent
                        .into_iter()
                        .filter(|c| c.coin_id.as_str() > cursor)
                        .collect(),
                    None => unspent,
                };
                let page_size = limit as usize;
                // This tier answers with the whole set in one call and has no cursor to push the
                // page down into, so the bound is on the RESPONSE. The upstream call count is one
                // per request either way.
                let complete = remaining.len() <= page_size;
                let coins: Vec<WalletCoin> = remaining.into_iter().take(page_size).collect();
                Ok(WalletCoinsResult {
                    cursor: coins.last().map(|c| c.coin_id.clone()),
                    complete,
                    coins,
                    source,
                    // The replica neither produced these coins nor bounds their freshness (#2233).
                    synced: false,
                    peak_height: None,
                })
            }
        }
    }

    /// ONE coin looked up by COIN ID (dig_ecosystem#2392).
    ///
    /// The read a caller polling a spend needs: "did the coin I created appear, and is the coin I
    /// funded it with gone?" Neither question can be asked by address.
    ///
    /// # Absence is an ANSWER; unreachable is an ERROR
    ///
    /// `coin: None` means a chain source ANSWERED and reported no such coin; every way of failing
    /// to get an answer at all is a [`BalanceError`]. Collapsing the two would make an outage look
    /// like a mint that never happened.
    ///
    /// **What `None` does NOT yet mean.** It is not proof the chain has no such coin. Today the
    /// tier underneath (`chia-query` 0.6) returns a single peer's empty coin-state list as `None`
    /// without consulting coinset, and that peer may be a block behind, mid-reorg, pruning, or
    /// hostile. So a caller polling a mint MUST treat `None` as "not seen yet" and keep polling —
    /// never as "this mint will never land". Requiring corroboration before believing an absence
    /// is dig_ecosystem#2456, one crate down; this method's shape does not change when it lands.
    ///
    /// **A POSITIVE answer is bound in IDENTITY only, and carries the same caveat otherwise.** A
    /// coin id is self-certifying, so the fallback tier rejects a record whose
    /// `SHA256(parent ‖ puzzle_hash ‖ amount)` is not the id asked for
    /// ([`super::fallback::CoinsetFallback`]) and a substituted coin surfaces as an error. That
    /// authenticates WHICH coin the record describes — it does not authenticate whether that coin
    /// is on chain, at what height it was created, or whether it has been spent. `created_height`
    /// and `spent_height` still come from ONE unauthenticated peer's answer, exactly as `None`
    /// does, and those two fields are the entire reason this method exists. A peer that watched
    /// the mempool knows a pending coin's preimage, so it can report a `created_height` for a coin
    /// that never landed and pass the binding check. Corroboration (dig_ecosystem#2456) must cover
    /// positive state, not only absence.
    ///
    /// # A HIT in the replica is answered from it; a MISS is not an answer at all
    ///
    /// This read does NOT go through [`routing::route`]. That router keys on whether the coin's
    /// puzzle hash is one the node derives — which is not known until AFTER the coin is read — and
    /// the local `coins` replica is populated only from the node's own subscriptions, so a MISS
    /// there means "this node does not watch that coin", which is NOT absence; serving it as
    /// absence would declare a live mint dead. So a miss falls through to the chain tier, always.
    ///
    /// A HIT is different, and reporting it as `source: fallback, synced: false` was
    /// dig_ecosystem#2938: the node held the coin, knew the height it held it as of, and told every
    /// caller it knew nothing. A warrant no read can ever carry is not strictness — it turns every
    /// consumer-side guard built on it into an unconditional refusal, which is how a guarded mint
    /// poll came to end in "the chain could not be reached" on a healthy node.
    ///
    /// So the three fields describe WHAT ANSWERED THIS READ, exactly as the address-scoped reads
    /// do:
    ///
    /// - the replica HOLDS the coin and is authoritative
    ///   ([`replica_is_authoritative`](Self::replica_is_authoritative)) — `source: db`, the
    ///   replica's own `peak_height`, and `synced` measured by
    ///   [`replica_answer_is_current`](Self::replica_answer_is_current) rather than assumed;
    /// - anything else — the chain tier answers, and says so: `source: fallback`, `synced: false`,
    ///   `peak_height: null`. A caller bounding confirmations reads [`chain_peak`](Self::chain_peak).
    ///
    /// The eligibility test is the SAME one the money reads use, not a second spelling of it, so
    /// the replica cannot be trusted here at a moment it is distrusted there. The wrong answer this
    /// ordering can produce is `fallback` for a coin the replica could have served — a read that is
    /// merely more expensive. The opposite mistake would report an unwatched coin as proven absent.
    ///
    /// # The custody boundary (§908)
    ///
    /// A pure chain read of public data. One hex string in; no address, no key, no seed, no
    /// signature.
    pub async fn coin_by_id(
        &self,
        coin_id: &str,
    ) -> std::result::Result<WalletCoinByIdResult, BalanceError> {
        // A coin the replica holds is served from the replica, ahead of the liveness check and the
        // rate limiter: neither guards an egress this arm opens, and gating a purely local answer
        // on a third party's reachability is the falsehood #2938 removes.
        if let Some(answer) = self.replica_coin_by_id(coin_id).await? {
            return Ok(answer);
        }
        // A coin the chain tier already holds cached is answered from that cache, ahead of BOTH the
        // liveness check and the rate limiter (dig_ecosystem#3044, dig_ecosystem#3050).
        //
        // The limiter bounds EGRESS amplification against the third-party oracle; a cache hit sends
        // nothing, so charging it a token bounds nothing and spends the budget the misses need.
        // Gating it made the bucket unable to refill under a polling client — a stable equilibrium
        // in which a profile read could never succeed while the app that needed it was open.
        //
        // `is_live()` is the SAME reasoning one step over (dig_ecosystem#3050): a cached answer
        // needs no live source either, because the answer is already in hand. Consulting a third
        // party's reachability before serving bytes this node already holds gives availability away
        // for nothing, and does it on the reads a lineage walk re-reads most — a spent coin's record
        // is immutable, so the cached rows are permanent by design. It also compounds: a refusal
        // becomes a retry, and retries are what exhausted the limiter in the first place.
        //
        // The amplification bound is UNCHANGED: only a miss reaches a peer, and only misses are
        // charged.
        if let Some(coin) = self
            .fallback
            .cached_coin_record_by_id(coin_id)
            .await
            .map_err(|e| BalanceError::ReadFailed(e.to_string()))?
        {
            return Ok(WalletCoinByIdResult {
                coin: Some(coin_from_fallback(&coin)),
                source: Source::Fallback,
                synced: false,
                peak_height: None,
            });
        }
        // A MISS, however, still needs a live source, and the refusal here STAYS (#1851): no live
        // source means the answer is UNKNOWN, never "no such coin". `Ok(None)` would collapse "I
        // could not check" into "it does not exist", which on a lineage walk reads as *this coin is
        // the tip*.
        if !self.fallback.is_live() {
            return Err(BalanceError::NoChainSource);
        }
        // The same global bound the other open chain reads carry (#1957): this is an
        // unauthenticated loopback endpoint, so without it a local process could loop it into
        // egress amplification against the third-party oracle.
        if !self.fallback_rate.try_acquire() {
            return Err(BalanceError::RateLimited);
        }
        tracing::info!(
            tier = Source::Fallback.as_wire(),
            "coin-id read routed to the third-party chain oracle"
        );
        let coin = self
            .fallback
            .coin_record_by_id(coin_id)
            .await
            .map_err(|e| BalanceError::ReadFailed(e.to_string()))?;
        Ok(WalletCoinByIdResult {
            coin: coin.as_ref().map(coin_from_fallback),
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        })
    }

    /// The replica's own answer for `coin_id`, or `None` where it has none to give.
    ///
    /// `None` is deliberately the SAME value for both ways of having nothing to say — the replica
    /// is not authoritative, or it is and simply does not hold this coin — because the caller does
    /// the same thing with either: ask the chain. Distinguishing them here would invite a future
    /// caller to treat the second as proven absence, which for a replica populated only from this
    /// node's own subscriptions it never is.
    ///
    /// Freshness is MEASURED, not inherited from eligibility. `replica_is_authoritative` says the
    /// replica may answer for a scope; `replica_answer_is_current` says whether what it answered is
    /// at the tip. A replica that completed a catch-up and then fell behind still answers here, with
    /// its real peak, labelled stale (dig_ecosystem#2869).
    async fn replica_coin_by_id(
        &self,
        coin_id: &str,
    ) -> std::result::Result<Option<WalletCoinByIdResult>, BalanceError> {
        let db_err = |e: sqlx::Error| BalanceError::ReadFailed(e.to_string());
        if !self.replica_is_authoritative().await.map_err(db_err)? {
            return Ok(None);
        }
        let ids = [normalize_hex_id(coin_id)];
        let Some(row) = self
            .db
            .coins_by_ids(&ids)
            .await
            .map_err(db_err)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let coin = coin_from_row(&row).map_err(|e| BalanceError::ReadFailed(e.to_string()))?;
        // The peak is read HERE, inside the arm, because it describes the replica this answer came
        // from — it is not context for an answer taken elsewhere.
        let peak_height = self.db.sync_state().await.map_err(db_err)?.peak_height;
        Ok(Some(WalletCoinByIdResult {
            coin: Some(coin),
            source: Source::Db,
            synced: self.replica_answer_is_current(peak_height).await,
            peak_height,
        }))
    }

    /// The SPEND that spent one coin (dig_ecosystem#2572).
    ///
    /// The read that turns a coin record into a lineage: a record says a coin is GONE, and only the
    /// spend says what it became. Following a DID singleton forward — which is how a dig-profile is
    /// resolved — is this read applied repeatedly.
    ///
    /// # Absence is an ANSWER; unreachable is an ERROR
    ///
    /// `spend: None` means a chain source ANSWERED and holds no spend of that coin: it is unspent,
    /// or unknown. Which of the two is [`coin_by_id`](Self::coin_by_id)'s question, not this one's.
    /// Every failure to get an answer at all is a [`BalanceError`], because a caller walking a
    /// lineage reads "no spend" as *this is the tip* and stops — so a dropped connection served as
    /// absence produces a spend built against a singleton that has already moved on.
    ///
    /// # TWO reads, ONE answer, and a contradiction between them is fatal
    ///
    /// The chain tier's spend read carries no heights, so the coin record is read alongside it and
    /// the two are composed. That is not merely cosmetic: it makes the answer self-checking. A
    /// spend whose coin no record knows, or whose record calls the coin unspent, is a CONTRADICTION
    /// — a source disagreeing with itself — and this method fails closed rather than emitting a
    /// spend with an invented or absent `spent_height`. A caller cannot tell an invented height
    /// from a real one, so it must never be handed either.
    ///
    /// Both reads share ONE rate-limit token. The bound exists to stop a local process amplifying
    /// egress at the third-party oracle (#1957), and the pair is one caller-visible operation; two
    /// tokens per call would halve the visible budget for no gain in protection.
    ///
    /// # The custody boundary (§908)
    ///
    /// A pure chain read of public data. One hex string in; no address, no key, no seed, no
    /// signature — and a puzzle REVEAL is a program the chain already published, not a secret.
    pub async fn coin_spend(
        &self,
        coin_id: &str,
    ) -> std::result::Result<WalletCoinSpendResult, BalanceError> {
        let read_err = |e: Error| BalanceError::ReadFailed(e.to_string());
        // Both halves of the composed answer, from the cache, before any token is spent AND before
        // the liveness check (dig_ecosystem#3044, dig_ecosystem#3050) — see `coin_by_id` for why a
        // cache hit is neither what the limiter bounds nor something a live source is needed for.
        //
        // BOTH must be cached: a cached spend whose record is not cached still has to reach a peer
        // for the heights, and that read is egress like any other. So the partially-cached case is a
        // genuine MISS and keeps both the liveness check and the token below.
        if let (Some(spend), Some(record)) = (
            self.fallback
                .cached_coin_spend(coin_id)
                .await
                .map_err(read_err)?,
            self.fallback
                .cached_coin_record_by_id(coin_id)
                .await
                .map_err(read_err)?,
        ) {
            return Ok(WalletCoinSpendResult {
                spend: Some(composed_spend(&spend, &record, coin_id)?),
                source: Source::Fallback,
                synced: false,
                peak_height: None,
            });
        }
        // A miss still needs a live source: `spend: None` must mean a source ANSWERED and holds no
        // spend, never that none could be reached — a lineage walk reads absence as *this is the
        // tip* and stops.
        if !self.fallback.is_live() {
            return Err(BalanceError::NoChainSource);
        }
        if !self.fallback_rate.try_acquire() {
            return Err(BalanceError::RateLimited);
        }
        tracing::info!(
            tier = Source::Fallback.as_wire(),
            "coin-spend read routed to the third-party chain oracle"
        );
        let spend = self
            .fallback
            .coin_spend(coin_id)
            .await
            .map_err(|e| BalanceError::ReadFailed(e.to_string()))?;
        let spend = match spend {
            None => None,
            Some(spend) => {
                let record = self
                    .fallback
                    .coin_record_by_id(coin_id)
                    .await
                    .map_err(read_err)?
                    .ok_or_else(|| {
                        BalanceError::ReadFailed(format!(
                            "chain source reported a spend of {coin_id} and no record of that coin"
                        ))
                    })?;
                Some(composed_spend(&spend, &record, coin_id)?)
            }
        };
        Ok(WalletCoinSpendResult {
            spend,
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        })
    }

    /// ONE PAGE of the DIRECT children created by spending one coin — ONE hop
    /// (dig_ecosystem#2572).
    ///
    /// Composed with [`coin_spend`](Self::coin_spend), this is a lineage walk the CALLER drives.
    /// The node never recurses: a transitive walk over a caller-supplied id is unbounded work the
    /// caller cannot bound, on a token-less endpoint.
    ///
    /// # An empty page is an ANSWER
    ///
    /// `coins: []` means a chain was consulted and the parent created no children it knows of —
    /// usually because the parent is unspent. Every failure to consult one is a [`BalanceError`],
    /// for the same reason [`coin_spend`](Self::coin_spend) states: an empty list reads as *that
    /// spend created nothing*, which ends a lineage walk silently and early. That applies to a
    /// failure MID-page too: a short page is never marked complete to salvage a partial read.
    ///
    /// # Paged, in ASCENDING `coin_id` order
    ///
    /// `after_coin_id` resumes strictly after a child the caller was HANDED, and the order is total
    /// and stable because coin ids are unique fixed-length hex — so a page boundary names one
    /// position and a walk can neither skip nor repeat a child. `limit` is the caller's page size,
    /// already validated against the contract's bounds before it arrives here.
    ///
    /// # `complete` is derived from what REMAINS, never from whether the page filled
    ///
    /// One extra child is fetched past the page and then dropped. The cheap-looking alternative —
    /// `complete = coins.len() < limit` — agrees with this one on every input EXCEPT a child count
    /// that is an exact multiple of the page size, where it declares a truncated page whole. A
    /// caller walking a lineage reads that as *this branch ends here*, so it presents a partial
    /// lineage as a complete one and never learns otherwise.
    ///
    /// # Why the page is cut HERE and not upstream
    ///
    /// The chain tier answers a parent query with the parent's whole child set in one call; it has
    /// no cursor to push the paging down into. So the page bound is not protecting THIS node from
    /// the source — it bounds the RESPONSE, which is what the contract's frame-derived maximum is
    /// about. The upstream call count is one per request either way.
    pub async fn coins_by_parent(
        &self,
        parent_coin_id: &str,
        after_coin_id: Option<&str>,
        limit: u32,
    ) -> std::result::Result<WalletCoinsByParentResult, BalanceError> {
        if !self.fallback.is_live() {
            return Err(BalanceError::NoChainSource);
        }
        if !self.fallback_rate.try_acquire() {
            return Err(BalanceError::RateLimited);
        }
        tracing::info!(
            tier = Source::Fallback.as_wire(),
            "children read routed to the third-party chain oracle"
        );
        let mut children: Vec<WalletCoin> = self
            .fallback
            .coin_records_by_parent(parent_coin_id)
            .await
            .map_err(|e| BalanceError::ReadFailed(e.to_string()))?
            .iter()
            .map(coin_from_fallback)
            .collect();
        // The total, stable order the cursor names a position in. Sorted HERE rather than trusted
        // from the source: the tier underneath merges peer and coinset answers and promises no
        // order at all, and an order that varies between pages loses rows silently.
        children.sort_by(|a, b| a.coin_id.cmp(&b.coin_id));
        let remaining = match after_coin_id {
            Some(cursor) => children
                .into_iter()
                .filter(|c| c.coin_id.as_str() > cursor)
                .collect(),
            None => children,
        };
        let page_size = limit as usize;
        let complete = remaining.len() <= page_size;
        let coins: Vec<WalletCoin> = remaining.into_iter().take(page_size).collect();
        Ok(WalletCoinsByParentResult {
            cursor: coins.last().map(|c| c.coin_id.clone()),
            complete,
            coins,
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        })
    }

    /// The node's current chain peak (dig_ecosystem#2376).
    ///
    /// Its own method rather than a field on a balance, because a balance's `peak_height` is `null`
    /// on every fallback-tier answer by design (#2233) — so a caller bounding a claimed
    /// confirmation could not obtain one from a node whose replica has not synced, which is exactly
    /// the node that most needs to answer.
    ///
    /// Prefers the node's own replica and falls back to the chain tier when the replica has no
    /// height. `peak_height: None` means UNKNOWN and MUST NOT be read as height zero.
    pub async fn chain_peak(&self) -> std::result::Result<ChainPeak, BalanceError> {
        let read_err = |e: Error| BalanceError::ReadFailed(e.to_string());
        let replica_peak = self
            .db
            .sync_state()
            .await
            .map_err(|e| read_err(e.into()))?
            .peak_height;
        if let Some(peak_height) = replica_peak {
            return Ok(ChainPeak {
                peak_height: Some(peak_height),
                // The SAME measured predicate the balance and coin reads use
                // (dig_ecosystem#2869), not `db.is_synced()`. That flag is
                // `initial_sync_complete`: it latches once and is cleared only by a backwards
                // chain move, so a replica hundreds of blocks behind still satisfied it and this
                // endpoint still called its height current (dig-node#293).
                synced: self.replica_answer_is_current(Some(peak_height)).await,
            });
        }
        // The replica has no height, so answering means an OUTBOUND round to the chain tier —
        // since dig_ecosystem#2790 a concurrent ask of the node's OWN dialled peers, settled on
        // their agreement, rather than a read of a third-party oracle. `Ok(None)` from it is the
        // peers failing to agree, which this endpoint reports as an unknown height; it is never
        // repaired from a single source.
        //
        // The bound still applies, and for the same reason (#1957): this is an unauthenticated
        // loopback endpoint, so without it a local process (or a CORS-reflected origin) could loop
        // it into egress amplification — now against the peer set rather than against coinset,
        // which is if anything the more valuable resource to protect.
        //
        // Guarded HERE rather than inherited from the coin read, because a bound that lives inside
        // one method's fallback arm covers exactly that method -- and a caller bounding a claimed
        // confirmation calls THIS one.
        if !self.fallback_rate.try_acquire() {
            return Err(BalanceError::RateLimited);
        }
        let peak_height = self.fallback.peak_height().await.map_err(read_err)?;
        Ok(ChainPeak {
            peak_height,
            // A height the replica did not produce says nothing about the replica being caught up.
            synced: false,
        })
    }

    /// Push an ALREADY-SIGNED spend bundle to the network (dig_ecosystem#2376).
    ///
    /// # The custody boundary (§908)
    ///
    /// The bundle arrives complete. This method holds no key, derives none, and signs nothing — the
    /// node's role on the money path is to read chain state and to relay what somebody else signed.
    ///
    /// # Why the node's OWN coins are refused when live broadcast is off (§18.12)
    ///
    /// §908 governs the USER's key, which never enters the node. It says nothing about the node's
    /// own custodied wallet — which holds real $DIG (the tipping subsystem spends it) and which
    /// `sign_coin_spends` will sign with on request. So "somebody else signed it" is not, on its
    /// own, true of every bundle that arrives here: a token holder can obtain a bundle signed by
    /// the node's own key and hand it straight back for relay. That path would make
    /// `DIG_WALLET_ENABLE_LIVE_BROADCAST` decorative — the node would send its own money with the
    /// flag off, which is the one thing the flag exists to prevent.
    ///
    /// So while [`Self::node_custodied_spending`] is off, a bundle requiring a signature from any
    /// key this node custodies is [`PushError::NodeCustodiedSpend`] — asked of the KEYS rather than
    /// the puzzle hashes, because the node's own $DIG is a CAT and a CAT coin does not sit at its
    /// owner's p2 hash (see [`Self::spends_node_custodied_coin`]). Relaying a bundle signed by
    /// anyone ELSE stays open on every install, which is the capability this method was added for.
    ///
    /// # Outcomes
    ///
    /// A mempool refusal is `Ok` with `accepted: false`; failing to REACH a mempool is `Err`. A
    /// node with no pusher attached is [`PushError::NoChainSource`] — never a fabricated
    /// acceptance.
    pub async fn push_signed_bundle(
        &self,
        signed_bundle_hex: &str,
    ) -> std::result::Result<PushOutcome, PushError> {
        let bundle = super::chain::decode_signed_bundle(signed_bundle_hex)
            .map_err(|e| PushError::InvalidBundle(e.to_string()))?;
        if !self.node_custodied_spending && self.spends_node_custodied_coin(&bundle) {
            return Err(PushError::NodeCustodiedSpend);
        }
        let pusher = self.pusher.as_ref().ok_or(PushError::NoChainSource)?;
        let pushed = pusher.push(&bundle).await;

        // Reserve unless the bundle was DEFINITIVELY rejected — see [`Self::is_definitive_rejection`].
        //
        // A reservation failure does not fail the push. The bundle may already be in a public
        // mempool by this point, and reporting a push that did happen as an error would be a worse
        // lie than the double-selection this guards against.
        if !matches!(&pushed, Ok(o) if Self::is_definitive_rejection(o)) {
            if let Err(e) = self.reserve_pushed_bundle(&bundle).await {
                tracing::warn!(
                    error = %e,
                    "pushed bundle may be in flight but its coins could not be reserved; a second \
                     send inside the confirmation window may reselect them"
                );
            }
        }
        pushed.map_err(|e| PushError::Unreachable(e.to_string()))
    }

    /// Whether `outcome` is the network DEFINITIVELY refusing this bundle — the only case in which
    /// its inputs stay selectable (#348).
    ///
    /// # The asymmetry this exists to correct
    ///
    /// Reservation used to be gated on `outcome.accepted` alone, so the two directions failed
    /// OPPOSITE ways and **the cheap-to-lie direction was the unsafe one**:
    ///
    /// - **Under-claim** — a source denying it relayed what it did relay, or a transport that failed
    ///   AFTER transmitting — reserved nothing, so the coins returned to the selectable set while a
    ///   bundle carrying them was in flight. A second send inside the confirmation window could
    ///   reselect the same inputs: exactly the double-select window this family exists to close.
    /// - **Over-claim** reserved for the bounded `RESERVATION_TTL_MS`, which self-heals.
    ///
    /// A source that wants a coin reselected only has to say "not accepted". Under NC-12 every
    /// dialled peer is untrusted, so that is not an exotic failure — it is the assumed case. So an
    /// unconfirmed relay is now treated as POSSIBLY IN FLIGHT and held to the TTL, which is the
    /// discipline dig-account settled on for the in-process race.
    ///
    /// # What counts as definitive, and what this does NOT claim
    ///
    /// A refusal is definitive only when the mempool STATED its reason (`accepted == false` with a
    /// `rejection`). A bare `accepted: false` with no reason is an unexplained denial and is held.
    ///
    /// This does not make the flag trustworthy — a hostile source can fabricate a rejection string,
    /// and nothing here can verify one without an independent chain read. What it does is make the
    /// CHEAPEST lie, and the accidental case, land on the safe side: a silent denial and a
    /// post-transmit transport failure now hold the coins instead of freeing them.
    ///
    /// The TTL is deliberately NOT shortened to compensate for the wider hold. That would trade a
    /// double-select for a lockout, and a lockout is the worse failure — measured on dig-account as
    /// `available=4000000 selectable=0`, renewable indefinitely. Requiring a STATED reason is what
    /// keeps a genuine mempool rejection (a bad signature, say) from locking the user's coins for
    /// the full TTL.
    fn is_definitive_rejection(outcome: &PushOutcome) -> bool {
        !outcome.accepted && outcome.rejection.is_some()
    }

    /// Record an accepted bundle as in-flight and hold its inputs out of further selection.
    ///
    /// The fee is recovered by running the spends through `dig-clvm`. That is BEST-EFFORT and
    /// deliberately does not gate anything: this node relays bundles it did not build and did not
    /// sign (§908), so a validation failure here says nothing about whether the bundle is
    /// legitimate — the mempool has already accepted it. An uncomputable fee is stored as `None`
    /// and reported as `null`, never as zero.
    async fn reserve_pushed_bundle(&self, bundle: &SpendBundle) -> Result<()> {
        let now = super::custody::now_ms() as i64;
        let row = super::db::PendingTransactionRow {
            transaction_id: hex::encode(bundle.name()),
            bundle_hex: super::chain::encode_signed_bundle(bundle)?,
            fee: spend::run_and_validate(&bundle.coin_spends)
                .ok()
                .map(|r| r.fee.to_string()),
            submitted_at: now,
            expires_at: now + RESERVATION_TTL_MS,
            attempts: 1,
            reserved_coin_ids: bundle
                .coin_spends
                .iter()
                .map(|cs| hex::encode(cs.coin.coin_id()))
                .collect(),
        };
        self.db.reserve_spend(&row).await?;
        Ok(())
    }

    /// Whether this node could have signed any part of `bundle` itself.
    ///
    /// The question is deliberately about KEYS, not puzzle hashes. A coin's puzzle hash says where
    /// it sits, and the node's coins only sit at its own p2 hashes when they are bare XCH: a CAT
    /// sits at `CatArgs::curry_tree_hash(asset_id, p2_hash)`, and singleton/NFT/DID coins wrap the
    /// owner puzzle again. [`WalletSigner::sign`] does not care — it matches the REQUIRED BLS
    /// public key and signs — so a hash-literal guard would wave through the node's own $DIG while
    /// the node happily signed it away.
    ///
    /// Asking [`required_public_keys`] is the same derivation the signer decides on, so the guard
    /// cannot drift from what it guards, and it is complete over every puzzle wrapper that exists
    /// or is added later.
    ///
    /// Fails CLOSED: a bundle whose conditions will not evaluate is treated as custodied rather
    /// than relayed unexamined.
    fn spends_node_custodied_coin(&self, bundle: &SpendBundle) -> bool {
        let Ok(required) = required_public_keys(&bundle.coin_spends, self.agg_sig_data()) else {
            return true;
        };
        let custodied = self.node_custodied_public_keys();
        required.iter().any(|pk| custodied.contains(pk))
    }

    /// The network domain the consensus computes this node's required signatures under.
    fn agg_sig_data(&self) -> Bytes32 {
        if self.config.network_id == "testnet11" {
            TESTNET11_CONSTANTS.agg_sig_me_additional_data
        } else {
            MAINNET_CONSTANTS.agg_sig_me_additional_data
        }
    }

    /// Every BLS public key the NODE holds a signing key for, as far as this node can know it.
    ///
    /// Two sources, unioned because each alone has a blind spot:
    ///
    /// - the signer loaded right now — present during a session unlock, absent under the default
    ///   per-transaction grant;
    /// - [`WalletCustody::custodied_public_keys`], which covers both "sign, then push after the
    ///   grant expired" and — because it is persisted in the manifest — "restart, then push while
    ///   still locked".
    ///
    /// Deliberately NOT the configured WATCHED puzzle hashes: the node holds no key for those, and
    /// refusing them would block the legitimate third-party push this method exists to serve. The
    /// question here is custody, not interest.
    fn node_custodied_public_keys(&self) -> HashSet<PublicKey> {
        let mut keys = self.custodied_public_keys.read().unwrap().clone();
        if let Some(signer) = self.current_signer() {
            keys.extend(signer.public_keys());
        }
        if let Some(custody) = self.custody.as_ref() {
            keys.extend(custody.custodied_public_keys());
        }
        keys
    }

    // ---- session identity scoping (#407) ---------------------------------

    /// Record the CLIENT's PUBLIC identity for this session (#407): the puzzle hashes /
    /// addresses it declared on `login`. Reads (`get_sync_status`, `get_cats`, coins) are
    /// then scoped to these public puzzle hashes — NEVER the node's own coins, NEVER a
    /// private key (#217). A bare fingerprint login (no puzzle hashes/addresses) leaves any
    /// prior identity untouched and does NOT seed one.
    fn login(&self, req: &Login) -> LoginResponse {
        let mut phs: Vec<String> = Vec::new();
        if let Some(hashes) = &req.puzzle_hashes {
            phs.extend(hashes.iter().map(|h| normalize_ph(h)));
        }
        if let Some(addrs) = &req.addresses {
            for a in addrs {
                if let Some(ph) = decode_address(a) {
                    phs.push(normalize_ph(&ph));
                }
            }
        }
        phs.retain(|p| !p.is_empty());
        phs.sort();
        phs.dedup();
        if !phs.is_empty() {
            *self.identity.write().unwrap() = Some(SessionIdentity {
                fingerprint: req.fingerprint,
                puzzle_hashes: phs,
            });
        }
        LoginResponse {}
    }

    /// Clear the session identity (`logout`): the node stops tracking the client's wallet.
    fn logout(&self) -> LogoutResponse {
        *self.identity.write().unwrap() = None;
        LogoutResponse {}
    }

    /// The PUBLIC puzzle hashes a wallet-data read is scoped to: the logged-in session
    /// identity if a `login` seeded one, else the node's own configured puzzle hashes
    /// (legacy). Normalized lowercase hex. Empty ⇒ the node is not tracking any wallet, so
    /// scoped reads return nothing and `get_sync_status` reports the honest not-tracking
    /// state (never a silent synced-zero).
    fn scoped_identity(&self) -> Vec<String> {
        if let Some(id) = self.identity.read().unwrap().as_ref() {
            if !id.puzzle_hashes.is_empty() {
                return id.puzzle_hashes.clone();
            }
        }
        self.config
            .puzzle_hashes
            .iter()
            .map(|p| normalize_ph(p))
            .collect()
    }

    /// The candidate coin set for a wallet-data read of `asset_id`, sourced per the B.6
    /// routing table: the local DB once synced, else the coinset fallback (so the caller
    /// never blocks on an unsynced replica).
    async fn wallet_coins(&self, asset_id: Option<&str>) -> Result<Vec<CoinRecord>> {
        // Scope EVERY wallet-data read to the connected client's PUBLIC identity (#407) —
        // never the node's own coins. An empty identity ⇒ not tracking ⇒ no coins.
        let identity = self.scoped_identity();
        // Coverage of the CLIENT's scope, never the bare `initial_sync_complete` flag: the DB was
        // only ever asked to follow the addresses a catch-up ran over, so querying it for an
        // uncovered identity returns `[]` — which downstream reads as "a chain was consulted and
        // this wallet is empty" (dig_ecosystem#2878).
        let covered = self.replica_covers_client_scope(&identity).await?;
        match routing::route(covered, true) {
            Source::Db => {
                let rows = self.db.coins_scoped(asset_id, &identity).await?;
                Ok(rows
                    .iter()
                    .filter(|c| c.asset_id.as_deref() == asset_id)
                    .map(|c| self.coin_row_to_record(c))
                    .collect())
            }
            Source::Fallback => {
                // dig-node#306. This arm used to `return Ok(Vec::new())` for ANY CAT, so a real
                // $DIG holder on an unsynced replica read as holding NONE — the mirror image of
                // dig_ecosystem#2879's over-report, and money-class for the same reason: a caller
                // cannot tell "you hold nothing" from "this tier declined to look."
                //
                // The blocker its comment named — *"CAT asset attribution while syncing needs
                // puzzle uncurrying"* — does not exist. A CAT coin is identified by WHERE IT
                // SITS, not by uncurrying it, so `asset_scoped_fallback_coins` scopes a hint read
                // to one asset with no uncurrying at all. It is the SAME helper
                // `balance_for_address` and `coins_for_address` already use, called here rather
                // than re-derived: the balance and the coin list behind it must not be able to
                // scope to different assets (§2.0 — one behaviour, one implementation).
                let asset = BalanceAsset::from_asset_id_hex(asset_id)?;
                let coins = self.asset_scoped_fallback_coins(asset, &identity).await?;
                Ok(coins
                    .iter()
                    .map(|c| self.fallback_coin_to_record(c))
                    .collect())
            }
        }
    }

    // ---- method implementations ------------------------------------------

    fn get_version(&self) -> GetVersionResponse {
        GetVersionResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// The connected wallet's sync state (#407), scoped to the client's PUBLIC identity and
    /// reported TRUTHFULLY:
    ///
    /// - `selectable_balance` sums ONLY the identity's unspent XCH coins (never the node's
    ///   own coins). An identity the node isn't tracking sums to 0.
    /// - The sync flag the client derives as `synced_coins >= total_coins` (with
    ///   `total_coins == 0` treated as synced) is made HONEST: the node reports synced ONLY
    ///   when it is tracking the identity AND the DB has completed its initial catch-up.
    ///   Otherwise it reports `synced_coins < total_coins` (`0` of at-least-`1`), so the
    ///   client sees "syncing"/"not tracking" and NEVER adopts a silent synced-zero (the
    ///   #399 root cause: an empty/unsynced DB previously forced `synced_coins==total_coins`
    ///   and read as synced with balance 0).
    async fn get_sync_status(&self) -> Result<GetSyncStatusResponse> {
        let identity = self.scoped_identity();
        let tracking = !identity.is_empty();
        // The SAME predicate `wallet_coins` routes on, so the coin list and the completeness
        // claim about it cannot come to disagree (dig_ecosystem#2878).
        let db_synced = self.replica_covers_client_scope(&identity).await?;
        let balance = if tracking {
            self.db.balance_scoped(None, &identity).await?
        } else {
            0
        };
        let known = if tracking {
            self.db.coin_count_scoped(&identity).await?
        } else {
            0
        };
        let (synced_coins, total_coins) = if tracking && db_synced {
            // Tracking + caught up ⇒ synced (an empty-but-synced wallet is `0 == 0` = synced).
            (known, known)
        } else {
            // Not tracking, or still catching up ⇒ honestly NOT synced: force
            // `synced_coins < total_coins` so the client shows syncing, never a silent 0.
            (0, known.max(1))
        };
        Ok(GetSyncStatusResponse {
            selectable_balance: Amount::u128(balance),
            unit: Unit::xch(),
            synced_coins,
            total_coins,
            receive_address: self.config.receive_address.clone(),
            burn_address: self.burn_address(),
            unhardened_derivation_index: self.db.max_derivation_index(false).await?,
            hardened_derivation_index: self.db.max_derivation_index(true).await?,
            checked_files: 0,
            total_files: 0,
            database_size: 0,
        })
    }

    fn check_address(&self, req: &CheckAddress) -> CheckAddressResponse {
        // Valid iff it decodes as bech32m AND its puzzle hash is one the wallet tracks.
        let owned = decode_address(&req.address)
            .map(|ph| {
                self.config
                    .puzzle_hashes
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(&ph))
            })
            .unwrap_or(false);
        CheckAddressResponse { valid: owned }
    }

    async fn get_derivations(&self, req: &GetDerivations) -> Result<GetDerivationsResponse> {
        let (rows, total) = self
            .db
            .get_derivations(req.hardened, req.offset, req.limit)
            .await?;
        Ok(GetDerivationsResponse {
            derivations: rows
                .into_iter()
                .map(|d| DerivationRecord {
                    index: d.index as u32,
                    public_key: d.public_key,
                    address: d.address,
                })
                .collect(),
            total,
        })
    }

    async fn get_coins(&self, req: &GetCoins) -> Result<GetCoinsResponse> {
        let mut coins = self.wallet_coins(req.asset_id.as_deref()).await?;
        coins.retain(|c| filter_matches(c, req.filter_mode));
        sort_coins(&mut coins, req.sort_mode, req.ascending);
        let total = coins.len() as u32;
        let page = paginate(coins, req.offset, req.limit);
        Ok(GetCoinsResponse { coins: page, total })
    }

    async fn get_coins_by_ids(&self, req: &GetCoinsByIds) -> Result<GetCoinsByIdsResponse> {
        let coins = self.coins_by_ids(&req.coin_ids).await?;
        Ok(GetCoinsByIdsResponse { coins })
    }

    /// Fetch coins by id honoring the routing table: synced → DB, with any ids missing
    /// from the DB (out-of-DB/arbitrary lookups) served from the fallback; syncing → all
    /// from the fallback.
    async fn coins_by_ids(&self, ids: &[String]) -> Result<Vec<CoinRecord>> {
        if routing::route(self.synced().await?, true) == Source::Db {
            let rows = self.db.coins_by_ids(ids).await?;
            let mut out: Vec<CoinRecord> =
                rows.iter().map(|c| self.coin_row_to_record(c)).collect();
            let found: Vec<String> = out.iter().map(|c| c.coin_id.clone()).collect();
            for id in ids.iter().filter(|id| !found.contains(id)) {
                if let Some(fc) = self.fallback.coin_record_by_id(id).await? {
                    out.push(self.fallback_coin_to_record(&fc));
                }
            }
            Ok(out)
        } else {
            let mut out = Vec::new();
            for id in ids {
                if let Some(fc) = self.fallback.coin_record_by_id(id).await? {
                    out.push(self.fallback_coin_to_record(&fc));
                }
            }
            Ok(out)
        }
    }

    async fn get_spendable_coin_count(
        &self,
        req: &GetSpendableCoinCount,
    ) -> Result<GetSpendableCoinCountResponse> {
        let coins = self.wallet_coins(req.asset_id.as_deref()).await?;
        let count = coins.iter().filter(|c| is_spendable(c)).count() as u32;
        Ok(GetSpendableCoinCountResponse { count })
    }

    async fn get_are_coins_spendable(
        &self,
        req: &GetAreCoinsSpendable,
    ) -> Result<GetAreCoinsSpendableResponse> {
        let coins = self.coins_by_ids(&req.coin_ids).await?;
        // Every requested coin must be present AND spendable (confirmed + unspent).
        let spendable = req
            .coin_ids
            .iter()
            .all(|id| coins.iter().any(|c| &c.coin_id == id && is_spendable(c)));
        Ok(GetAreCoinsSpendableResponse { spendable })
    }

    /// One token's metadata and the connected client's balance in it (`get_token`, `get_cats`,
    /// `get_all_cats`), gated on the replica actually COVERING that client's scope (dig-node#247).
    ///
    /// # A zero that means "I did not look" must not be spelled like a zero that means "empty"
    ///
    /// This read answered `db.balance_scoped` with no gate at all — not even the bare `synced()`
    /// flag its sibling had. A client whose addresses the catch-up never ran over queries a
    /// replica that holds none of its coins, gets `0`, and `TokenRecord` carries no completeness
    /// field for that zero to stand beside. And `login` does not enrol — enrolment is
    /// `control.wallet.watch` — so a client that logs in without enrolling is never covered and
    /// its balance stays `0` indefinitely. No amount of waiting fixes it.
    ///
    /// The gate is [`Self::replica_covers_client_scope`], the SAME predicate `get_coins` and
    /// `get_sync_status` route on (dig_ecosystem#2878), so the balance and the coin list cannot
    /// come to disagree about whether the view is complete. It is deliberately NOT
    /// `replica_is_authoritative`, which is VACUOUS here: under §908 the node holds no custody
    /// and may hold no registrations, so its followed set is empty, every recording contains it,
    /// and an uncovered client would be served the same confident zero as before.
    ///
    /// # The two assets take different remedies, because only one of them HAS the XCH remedy
    ///
    /// **XCH** falls to the chain, exactly as `get_coins` now does: the coins sit AT the client's
    /// puzzle hashes, so the fallback tier can be asked directly and the answer is real.
    ///
    /// **A CAT is REFUSED.** A CAT coin does not sit at its owner's puzzle hash — it is hinted to
    /// it — and telling which asset a hinted coin belongs to needs puzzle uncurrying, which the
    /// fallback tier does not perform. So routing a CAT read to the chain returns an EMPTY set,
    /// which is the same confident zero arriving through a different door. `TokenRecord` cannot
    /// spell "unknown" without a `dig-node-control-interface` contract change, and a contract
    /// change publishes first; refusing is the smallest honest option available today, and unlike
    /// a zero it is a shape no caller can mistake for a figure.
    async fn token_record(&self, asset_id: Option<&str>) -> Result<TokenRecord> {
        // Balances are scoped to the connected client's PUBLIC identity (#407).
        let identity = self.scoped_identity();
        let covered = self.replica_covers_client_scope(&identity).await?;
        match asset_id {
            None => {
                let bal = self.scoped_xch_balance(&identity, covered).await?;
                Ok(TokenRecord {
                    asset_id: None,
                    name: Some("Chia".into()),
                    ticker: Some("XCH".into()),
                    precision: 12,
                    description: None,
                    icon_url: None,
                    visible: true,
                    balance: Amount::u128(bal),
                    selectable_balance: Amount::u128(bal),
                    revocation_address: None,
                })
            }
            Some(a) => {
                if !covered {
                    return Err(Self::uncovered_scope_error("this CAT balance"));
                }
                let bal = self.db.balance_scoped(Some(a), &identity).await?;
                let meta = self.db.cat(a).await?;
                Ok(TokenRecord {
                    asset_id: Some(a.to_string()),
                    name: meta.as_ref().and_then(|m| m.name.clone()),
                    ticker: meta.as_ref().and_then(|m| m.ticker.clone()),
                    precision: meta.as_ref().map(|m| m.precision as u8).unwrap_or(3),
                    description: meta.as_ref().and_then(|m| m.description.clone()),
                    icon_url: meta.as_ref().and_then(|m| m.icon_url.clone()),
                    visible: meta.as_ref().map(|m| m.visible).unwrap_or(true),
                    balance: Amount::u128(bal),
                    selectable_balance: Amount::u128(bal),
                    revocation_address: None,
                })
            }
        }
    }

    /// The client's confirmed unspent XCH, taken from whichever tier is entitled to answer.
    ///
    /// The chain arm re-applies `balance_scoped`'s own predicate — confirmed and unspent — rather
    /// than summing whatever the fallback returned. `coin_records_by_puzzle_hashes` includes
    /// RECENTLY SPENT coins by design, so summing it raw would report money the user has already
    /// spent as money they still hold, which is a falsehood in the opposite direction and a worse
    /// one to act on.
    async fn scoped_xch_balance(&self, identity: &[String], covered: bool) -> Result<u128> {
        if covered {
            return Ok(self.db.balance_scoped(None, identity).await?);
        }
        if !self.fallback.is_live() {
            return Err(Self::uncovered_scope_error("this balance"));
        }
        let coins = self
            .fallback
            .coin_records_by_puzzle_hashes(identity)
            .await?;
        Ok(coins
            .iter()
            .filter(|c| c.spent_height.is_none() && c.created_height.is_some())
            .map(|c| u128::from(c.amount))
            .sum())
    }

    /// The one refusal message every uncovered token read shares, so an operator reading a 503
    /// learns the ACTIONABLE fact — that enrolment, not waiting, is what fixes it.
    fn uncovered_scope_error(subject: &str) -> Error {
        Error::unavailable(format!(
            "the wallet replica does not cover this client's addresses, so {subject} is unknown \
             rather than zero; enrol the address with control.wallet.watch"
        ))
    }

    async fn get_cats(&self) -> Result<GetCatsResponse> {
        // Scope to the connected client's PUBLIC identity (#407): the CATs whose coins are
        // hinted to the client's puzzle hashes, not every CAT in the node's DB.
        let identity = self.scoped_identity();
        // Gated here as well as in `token_record`, because the LIST is itself a replica read: an
        // uncovered scope yields no asset ids at all, so every per-token gate downstream is
        // skipped and the caller is told it owns no CATs (dig-node#247).
        if !self.replica_covers_client_scope(&identity).await? {
            return Err(Self::uncovered_scope_error("the CATs this wallet owns"));
        }
        let ids = self.db.owned_cat_asset_ids_scoped(&identity).await?;
        let mut cats = Vec::with_capacity(ids.len());
        for id in ids {
            cats.push(self.token_record(Some(&id)).await?);
        }
        Ok(GetCatsResponse { cats })
    }

    async fn get_all_cats(&self) -> Result<GetAllCatsResponse> {
        let rows = self.db.all_cats().await?;
        let mut cats = Vec::with_capacity(rows.len());
        for r in rows {
            cats.push(self.token_record(Some(&r.asset_id)).await?);
        }
        Ok(GetAllCatsResponse { cats })
    }

    async fn get_token(&self, req: &GetToken) -> Result<GetTokenResponse> {
        Ok(GetTokenResponse {
            token: Some(self.token_record(req.asset_id.as_deref()).await?),
        })
    }

    async fn is_asset_owned(&self, req: &IsAssetOwned) -> Result<IsAssetOwnedResponse> {
        Ok(IsAssetOwnedResponse {
            owned: self.db.is_asset_owned(&req.asset_id).await?,
        })
    }

    // NFT/DID reads: served from the tables the sync reconstruction populates
    // ([`crate::sage::singleton`]). A wallet with no such assets returns an empty list.
    async fn get_dids(&self) -> Result<GetDidsResponse> {
        let rows = self.db.all_dids().await?;
        let dids = rows
            .iter()
            .filter_map(|r| serde_json::from_str::<DidRecord>(&r.record_json).ok())
            .collect();
        Ok(GetDidsResponse { dids })
    }

    async fn get_nfts(&self, req: &GetNfts) -> Result<GetNftsResponse> {
        let rows = self.db.all_nfts().await?;
        let matches = |r: &super::db::NftDbRow| -> bool {
            let coll_ok = match &req.collection_id {
                Some(c) => r.collection_id.as_deref() == Some(c.as_str()),
                None => true,
            };
            let minter_ok = match &req.minter_did_id {
                Some(m) => r.minter_did.as_deref() == Some(m.as_str()),
                None => true,
            };
            let owner_ok = match &req.owner_did_id {
                Some(o) => r.owner_did.as_deref() == Some(o.as_str()),
                None => true,
            };
            let name_ok = match &req.name {
                Some(n) => r
                    .name
                    .as_deref()
                    .map(|rn| rn.contains(n.as_str()))
                    .unwrap_or(false),
                None => true,
            };
            coll_ok && minter_ok && owner_ok && name_ok
        };
        let mut nfts: Vec<NftRecord> = rows
            .iter()
            .filter(|r| req.include_hidden || r.visible)
            .filter(|r| matches(r))
            .filter_map(|r| serde_json::from_str::<NftRecord>(&r.record_json).ok())
            .collect();
        match req.sort_mode {
            NftSortMode::Name => nfts.sort_by(|a, b| a.name.cmp(&b.name)),
            NftSortMode::Recent => nfts.sort_by_key(|n| std::cmp::Reverse(n.created_height)),
        }
        let total = nfts.len() as u32;
        let page = nfts
            .into_iter()
            .skip(req.offset as usize)
            .take(req.limit as usize)
            .collect();
        Ok(GetNftsResponse { nfts: page, total })
    }

    async fn get_nft(&self, req: &GetNft) -> Result<GetNftResponse> {
        let launcher = normalize_singleton_id(&req.nft_id);
        let nft = self
            .db
            .nft(&launcher)
            .await?
            .and_then(|r| serde_json::from_str::<NftRecord>(&r.record_json).ok());
        Ok(GetNftResponse { nft })
    }

    async fn get_nft_data(&self, req: &GetNftData) -> Result<GetNftDataResponse> {
        let launcher = normalize_singleton_id(&req.nft_id);
        let Some(_row) = self.db.nft(&launcher).await? else {
            return Ok(GetNftDataResponse { data: None });
        };
        // The off-chain data blob + CHIP-0015 metadata JSON are fetched opportunistically; a
        // synced wallet always knows the on-chain URIs/hashes (in the NftRecord). When the
        // metadata JSON has been fetched, surface it; the raw blob fetch is a follow-on.
        let metadata_json = self.db.nft_metadata_json(&launcher).await?;
        Ok(GetNftDataResponse {
            data: Some(NftData {
                blob: None,
                mime_type: None,
                hash_matches: false,
                metadata_hash_matches: metadata_json.is_some(),
                metadata_json,
            }),
        })
    }

    async fn get_nft_collections(
        &self,
        req: &GetNftCollections,
    ) -> Result<GetNftCollectionsResponse> {
        let rows = self.db.all_nft_collections().await?;
        let all: Vec<NftCollectionRecord> = rows
            .iter()
            .filter(|r| req.include_hidden || r.visible)
            .filter_map(|r| serde_json::from_str::<NftCollectionRecord>(&r.record_json).ok())
            .collect();
        let total = all.len() as u32;
        let collections = all
            .into_iter()
            .skip(req.offset as usize)
            .take(req.limit as usize)
            .collect();
        Ok(GetNftCollectionsResponse { collections, total })
    }

    async fn get_nft_collection(&self, req: &GetNftCollection) -> Result<GetNftCollectionResponse> {
        let collection = match &req.collection_id {
            Some(id) => self
                .db
                .nft_collection(id)
                .await?
                .and_then(|r| serde_json::from_str::<NftCollectionRecord>(&r.record_json).ok()),
            None => None,
        };
        Ok(GetNftCollectionResponse { collection })
    }

    // Transactions are derived from the coin table grouped by created/spent height.
    async fn get_transactions(&self, req: &GetTransactions) -> Result<GetTransactionsResponse> {
        let mut txns = self.derive_transactions().await?;
        txns.sort_by(|a, b| {
            if req.ascending {
                a.height.cmp(&b.height)
            } else {
                b.height.cmp(&a.height)
            }
        });
        let total = txns.len() as u32;
        let page: Vec<_> = txns
            .into_iter()
            .skip(req.offset as usize)
            .take(req.limit as usize)
            .collect();
        Ok(GetTransactionsResponse {
            transactions: page,
            total,
        })
    }

    async fn get_transaction(&self, req: &GetTransaction) -> Result<GetTransactionResponse> {
        let txns = self.derive_transactions().await?;
        Ok(GetTransactionResponse {
            transaction: txns.into_iter().find(|t| t.height == req.height),
        })
    }

    /// The bundles this node has pushed and not yet observed settling
    /// (dig_ecosystem#2764).
    ///
    /// This returned a hardcoded empty list, under a comment explaining that no spend path
    /// existed. The comment was true when written and had been false since `push_signed_bundle`
    /// landed: a caller that pushed a bundle and polled here was told, as a measured fact, that
    /// nothing was in flight.
    ///
    /// Lapsed reservations are retired before reading, so a bundle whose expiry has passed is not
    /// reported as live. That is done here, on the read, because it is the moment the answer has
    /// to be true — a sweep on some other schedule would leave a window where this surface
    /// reported a bundle the wallet had already stopped holding coins for.
    ///
    /// Returns `Err` on a database failure rather than an empty list. An empty list is a CLAIM —
    /// "nothing is in flight" — and this surface must never make one it cannot support.
    async fn get_pending_transactions(&self) -> Result<GetPendingTransactionsResponse> {
        self.db
            .prune_reservations(super::custody::now_ms() as i64)
            .await?;
        let mut transactions = Vec::new();
        for t in self.db.pending_transactions().await? {
            // An absent fee stays absent, and a fee that will not parse is an ERROR rather than a
            // zero. A stored fee was written from a `u64`, so an unparseable one means the table
            // is corrupt; reporting "fee: 0" for it would be the confident-wrong-number-about-
            // money failure this ticket exists to remove.
            let fee = match &t.fee {
                None => None,
                Some(raw) => Some(Amount::u64(raw.parse::<u64>().map_err(|e| {
                    Error::internal(format!(
                        "pending transaction {} has an unreadable fee {raw:?}: {e}",
                        t.transaction_id
                    ))
                })?)),
            };
            transactions.push(PendingTransactionRecord {
                transaction_id: t.transaction_id,
                fee,
                submitted_at: Some(t.submitted_at.max(0) as u64),
            });
        }
        Ok(GetPendingTransactionsResponse { transactions })
    }

    /// Group the wallet's coins into per-height transaction records (created vs spent).
    async fn derive_transactions(&self) -> Result<Vec<TransactionRecord>> {
        use std::collections::BTreeMap;
        let coins = self.db.all_coins().await?;
        let mut by_height: BTreeMap<u32, (Vec<TransactionCoinRecord>, Vec<TransactionCoinRecord>)> =
            BTreeMap::new();
        for c in &coins {
            let rec = self.tx_coin_record(c);
            if let Some(h) = c.created_height {
                by_height.entry(h as u32).or_default().1.push(rec.clone());
            }
            if let Some(h) = c.spent_height {
                by_height.entry(h as u32).or_default().0.push(rec);
            }
        }
        Ok(by_height
            .into_iter()
            .map(|(height, (spent, created))| TransactionRecord {
                height,
                timestamp: None,
                spent,
                created,
            })
            .collect())
    }

    fn tx_coin_record(&self, c: &CoinRow) -> TransactionCoinRecord {
        TransactionCoinRecord {
            coin_id: c.coin_id.clone(),
            amount: Amount::u128(c.amount.parse::<u128>().unwrap_or(0)),
            address: Some(self.address_of(&c.puzzle_hash)),
            address_kind: AddressKind::Own,
            asset: self.coin_asset(c),
        }
    }

    fn coin_asset(&self, c: &CoinRow) -> Asset {
        match &c.asset_id {
            None => Asset {
                asset_id: None,
                name: Some("Chia".into()),
                ticker: Some("XCH".into()),
                precision: 12,
                icon_url: None,
                description: None,
                is_sensitive_content: false,
                is_visible: true,
                revocation_address: None,
                kind: AssetKind::Token,
            },
            Some(a) => Asset {
                asset_id: Some(a.clone()),
                name: None,
                ticker: None,
                precision: 3,
                icon_url: None,
                description: None,
                is_sensitive_content: false,
                is_visible: true,
                revocation_address: None,
                kind: AssetKind::Token,
            },
        }
    }

    fn get_key(&self, req: &GetKey) -> GetKeyResponse {
        // A single loaded wallet; return it when the fingerprint matches or is null.
        let key = self
            .config
            .key
            .clone()
            .filter(|k| req.fingerprint.map(|f| f == k.fingerprint).unwrap_or(true));
        GetKeyResponse { key }
    }

    fn get_keys(&self) -> GetKeysResponse {
        GetKeysResponse {
            keys: self.config.key.clone().into_iter().collect(),
        }
    }

    // ---- send/spend method group (#216) ----------------------------------

    /// The wallet's tracked p2 puzzle hashes (for summary "receiving" flags).
    fn wallet_puzzle_hashes(&self) -> HashSet<Bytes32> {
        if let Some(s) = self.current_signer() {
            return s.puzzle_hashes();
        }
        self.config
            .puzzle_hashes
            .iter()
            .filter_map(|h| singleton::bytes32_from_hex(h).ok())
            .collect()
    }

    /// The EFFECTIVE signing key (#368/#432): the bring-up-injected signer if present (tests/simulator
    /// win), else — when the node-managed unlock authority (§18.24) is attached — the AUTH-GATED
    /// signer (a per-transaction one-shot grant, or the held session signer in session-unlock-all
    /// mode; `None` when only a read-only session is active). With NO auth attached, the legacy path:
    /// the signer of the currently-unlocked node custody. `None` ⇒ the wallet is locked for signing.
    /// Returns an owned `Arc` because the gated signer lives behind another lock, so it cannot be
    /// borrowed out of `&self`.
    fn current_signer(&self) -> Option<Arc<WalletSigner>> {
        let signer = self.resolve_signer();
        if let Some(s) = signer.as_ref() {
            self.remember_custodied_public_keys(s);
        }
        signer
    }

    /// [`Self::current_signer`] without the bookkeeping — the resolution rule itself.
    fn resolve_signer(&self) -> Option<Arc<WalletSigner>> {
        if let Some(s) = self.signer.clone() {
            return Some(s);
        }
        None
    }

    /// Why [`Self::current_signer`] returned `None`, as one of the three published
    /// [`super::tipping::refusal`] strings (#410).
    ///
    /// The states are distinguished by what this backend can actually SEE — whether a custody view
    /// is attached at all, and whether that view holds any enrolled wallet — never by guessing. The
    /// single reason these replace, `"wallet is locked"`, was false in the state a shipped node is
    /// permanently in: `with_signer` has no non-test caller, so the signer is absent on an unlocked
    /// wallet just as surely as on a locked one, and telling the user to unlock sent them after a
    /// remedy that does not exist.
    ///
    /// Only meaningful when the signer is genuinely absent; callers reach it from the `else` arm.
    fn signer_absence_reason(&self) -> &'static str {
        use super::tipping::refusal;
        match self.custody.as_ref() {
            None => refusal::NO_SIGNER_CONFIGURED,
            Some(custody) if custody.any_wallet() => refusal::WALLET_ENROLLED_BUT_UNOPENABLE,
            Some(_) => refusal::NO_WALLET_ENROLLED,
        }
    }

    /// Record `signer`'s public keys so the push guard still recognises the node's own coins after
    /// the signer is gone (see [`Self::custodied_public_keys`]).
    ///
    /// Takes the write lock only when there is something new to add: a signer resolves on many
    /// read paths, and the set is stable after the first sight of a given wallet.
    fn remember_custodied_public_keys(&self, signer: &WalletSigner) {
        let keys = signer.public_keys();
        if keys.is_subset(&self.custodied_public_keys.read().unwrap()) {
            return;
        }
        self.custodied_public_keys.write().unwrap().extend(keys);
    }

    /// The signer, or a locked-wallet error (C.6: spends need node-custodied keys).
    fn require_signer(&self) -> Result<Arc<WalletSigner>> {
        self.current_signer()
            .ok_or_else(|| Error::internal("wallet is locked: no signing key available"))
    }

    /// The change puzzle hash (the wallet's first receive address).
    fn change_ph(&self) -> Result<Bytes32> {
        if let Some(ph) = self.current_signer().and_then(|s| s.change_puzzle_hash()) {
            return Ok(ph);
        }
        match self.config.puzzle_hashes.first() {
            Some(h) => singleton::bytes32_from_hex(h),
            None => Err(Error::internal("no change address available")),
        }
    }

    /// Decode a destination address to its puzzle hash.
    fn decode_ph(&self, address: &str) -> Result<Bytes32> {
        let hex = decode_address(address)
            .ok_or_else(|| Error::api(format!("invalid address: {address}")))?;
        singleton::bytes32_from_hex(&hex)
    }

    /// Refuse to select spend inputs from a replica that is not authoritative.
    ///
    /// The DISPLAY reads pass through [`routing::route`], which picks a tier; the spend-input
    /// readers did not, so they selected coins straight out of the local table even while
    /// `initial_sync_complete` was false — the tier gate that guards every displayed balance
    /// never guarded the money path at all. The table is written by a peer, and the
    /// subscription filter is no defence against the peer itself: the wallet HANDS it the
    /// puzzle-hash set, so every hash that passes the filter is one the peer was just given.
    ///
    /// # The four readers, and why the count matters
    ///
    /// An earlier version of this doc said "the two spend-input readers below", and there were
    /// four. The two it missed were the ones that matter most in practice:
    /// [`Self::select_cats`] is the **$DIG** path behind `send_cat`, `bulk_send_cat` and the
    /// node-custodied tip, and [`Self::singleton_parent_child`] is the single reader every
    /// NFT/DID/option spend resolves its input coin through. Naming a subset is how the previous
    /// round's finding recurred, so the complete list is written here and each entry is pinned
    /// by its own mutation-proved test:
    ///
    /// | reader | rows become | reached by |
    /// |---|---|---|
    /// | [`Self::spendable_coins`] | XCH inputs + every fee | `send_xch`, `combine`, `split`, mints |
    /// | [`Self::coins_from_ids`] | caller-named XCH inputs | `multi_send`, `combine`, `split` |
    /// | [`Self::select_cats`] | CAT/$DIG inputs | `send_cat`, `bulk_send_cat`, offers, the tip |
    /// | [`Self::singleton_parent_child`] | the singleton being spent | NFT/DID/option transfers |
    ///
    /// The last two were reachable UNGATED on the ordinary path: `select_cats` touched the gate
    /// only through its XCH *fee* coins, and only when `fee > 0`, while `resolve_offer_cats`
    /// passes fee `0` unconditionally and a plain `send_cat` does whenever the caller sets no
    /// fee. That is not a dormant hole — [`super::sync::handle_coin_state_update`] clears
    /// `initial_sync_complete` on any backwards move, so an ordinary reorg leaves the replica
    /// unauthoritative while a fee-0 CAT send proceeds from it.
    ///
    /// Refusing is the right failure. An unsynced replica cannot be corrected into a safe input
    /// set by falling back per-coin — the fallback tier can say a coin exists, but the *set* of
    /// spendable coins is exactly what the replica is not entitled to assert yet. The remedy is
    /// to finish an authoritative sync (an operator-chosen peer, or
    /// [`Self::refresh_tracked_coins`] off the chain-oracle tier), which is a state the caller
    /// can reach; a spend built from unverified inputs is not.
    async fn require_authoritative_coins(&self) -> Result<()> {
        if routing::route(self.synced().await?, true) == Source::Db {
            return Ok(());
        }
        Err(Error::internal(
            "the local coin replica is not authoritative (initial sync incomplete): refusing to \
             build a spend from it",
        ))
    }

    /// The spendable coins for an asset (`None` = XCH), as `chia_protocol::Coin`s.
    ///
    /// Gated on [`Self::require_authoritative_coins`] — this is a spend-input read, not a
    /// display read.
    ///
    /// Reads the UNRESERVED unspent set (dig_ecosystem#2763): a coin already committed to a
    /// bundle this node pushed is not offered again. Without that, two sends inside the
    /// confirmation window selected the same coin — the replica only learns a coin is spent when
    /// a peer pushes a `coin_state_update`, tens of seconds later — and the second was a
    /// guaranteed mempool refusal surfacing as an opaque `push failed`.
    ///
    /// This is deliberately the only read that changes. Balance and display reads keep counting a
    /// coin whose spend has not settled, because the chain has not said otherwise yet; "what do I
    /// own" and "what may I spend next" are different questions.
    async fn spendable_coins(&self, asset_id: Option<&str>) -> Result<Vec<Coin>> {
        self.require_authoritative_coins().await?;
        self.db
            .prune_reservations(super::custody::now_ms() as i64)
            .await?;
        let rows = self.db.unreserved_unspent_coins(asset_id).await?;
        rows.iter().map(singleton::coin_from_row).collect()
    }

    /// Fetch specific coins by id (all must exist), as `chia_protocol::Coin`s.
    ///
    /// Gated on [`Self::require_authoritative_coins`] for the same reason as
    /// [`Self::spendable_coins`]: naming a coin id does not make the row describing it any more
    /// verified than the rest of the table.
    async fn coins_from_ids(&self, ids: &[String]) -> Result<Vec<Coin>> {
        self.require_authoritative_coins().await?;
        let rows = self.db.coins_by_ids(ids).await?;
        if rows.len() != ids.len() {
            return Err(Error::not_found(
                "one or more coins not found in the wallet",
            ));
        }
        rows.iter().map(singleton::coin_from_row).collect()
    }

    /// Validate (dig-clvm), summarize, optionally sign+broadcast (only when a broadcaster is
    /// attached — NEVER in CI), and return the Sage `TransactionResponse`.
    async fn finalize_spend(
        &self,
        coin_spends: Vec<CoinSpend>,
        auto_submit: bool,
    ) -> Result<TransactionResponse> {
        spend::run_and_validate(&coin_spends)?;
        let summary = spend::summarize(
            &coin_spends,
            &self.config.address_prefix,
            &self.wallet_puzzle_hashes(),
        )?;
        if auto_submit {
            if let (Some(signer), Some(bc)) = (self.current_signer(), self.broadcaster.as_ref()) {
                let sig = signer.sign(&coin_spends)?;
                bc.broadcast(&SpendBundle::new(coin_spends.clone(), sig))
                    .await?;
            }
        }
        let coin_spends_json = coin_spends
            .iter()
            .map(spend::coin_spend_to_json)
            .collect::<Result<Vec<_>>>()?;
        Ok(TransactionResponse {
            summary,
            coin_spends: coin_spends_json,
        })
    }

    /// Build+sign+validate+broadcast a $DIG tip of `amount` base units to `recipient`, reusing the
    /// canonical `send_cat` path (coin selection + [`spend::build_cat_send`] = `Cat::spend_all`,
    /// never hand-rolled CLVM). The tipping engine (#378) drives this — it passes its OWN broadcaster
    /// so the backend's `broadcaster` field (unset on the shipped node) is bypassed and enabling
    /// tips never enables live broadcast for the whole wallet surface.
    ///
    /// Fail-closed contract (see [`super::tipping::TipSpender`]): definitively PRE-broadcast
    /// conditions (no signing key / no lineage / insufficient $DIG / build or validation failure)
    /// return [`TipSpendOutcome::NotExecutable`] (retryable — no money moved); the ONLY money-moving
    /// step is `broadcaster.broadcast`, whose error propagates as `Err` (ambiguous — the engine keeps
    /// the reservation and does not retry that day).
    pub async fn build_and_broadcast_dig_tip(
        &self,
        recipient: Bytes32,
        amount: u64,
        fee: u64,
        broadcaster: &dyn Broadcaster,
        confirmer: Option<&dyn super::spend::Confirmer>,
    ) -> Result<super::tipping::TipSpendOutcome> {
        use super::tipping::TipSpendOutcome;
        // Signer (node custody). Absence is retryable, not a spend failure — but WHY it is absent
        // is three different situations, and saying the wrong one sends the user somewhere useless.
        let Some(signer) = self.current_signer() else {
            return Ok(TipSpendOutcome::NotExecutable {
                reason: self.signer_absence_reason().into(),
            });
        };
        // CAT-send needs a lineage source to resolve input coins; absent ⇒ not-yet-synced.
        if self.lineage.is_none() {
            return Ok(TipSpendOutcome::NotExecutable {
                reason: "no lineage source (wallet not synced)".into(),
            });
        }
        let asset_hex = hex::encode(digstore_chain::dig::DIG_ASSET_ID);
        let (cats, xch_fee_coins) = match self.select_cats(&asset_hex, amount, fee).await {
            Ok(v) => v,
            Err(e) => {
                return Ok(TipSpendOutcome::NotExecutable {
                    reason: format!("cannot select $DIG coins: {e}"),
                })
            }
        };
        let change = match self.change_ph() {
            Ok(c) => c,
            Err(e) => {
                return Ok(TipSpendOutcome::NotExecutable {
                    reason: format!("no change address: {e}"),
                })
            }
        };
        // Build + validate (dig-clvm, fail-closed) — all PRE-broadcast, so a failure is retryable.
        let coin_spends = match spend::build_cat_send(
            signer.as_ref(),
            &cats,
            recipient,
            amount,
            change,
            true, // hint the recipient so their wallet sees the tip
            fee,
            &xch_fee_coins,
        ) {
            Ok(cs) => cs,
            Err(e) => {
                return Ok(TipSpendOutcome::NotExecutable {
                    reason: format!("tip build failed: {e}"),
                })
            }
        };
        let validated = match spend::run_and_validate(&coin_spends) {
            Ok(v) => v,
            Err(e) => {
                return Ok(TipSpendOutcome::NotExecutable {
                    reason: format!("tip validation failed: {e}"),
                })
            }
        };
        let sig = match signer.sign(&coin_spends) {
            Ok(s) => s,
            Err(e) => {
                return Ok(TipSpendOutcome::NotExecutable {
                    reason: format!("tip signing failed: {e}"),
                })
            }
        };
        let bundle = SpendBundle::new(coin_spends, sig);
        let txid = hex::encode(bundle.name());
        // The ONLY money-moving step. An error here is AMBIGUOUS → propagate (the engine keeps the
        // reservation, never retries that day).
        broadcaster.broadcast(&bundle).await?;
        // Best-effort on-chain confirmation (§18.12): poll for a created output coin. A confirmed
        // spend records the tip `Confirmed`; a miss/timeout (or no confirmer) records it `Pending`
        // with the txid — the money moved either way (broadcast succeeded), so confirmation is NEVER
        // treated as a spend failure. The confirm read is post-broadcast and its outcome only labels
        // the ledger status; it does not gate the money movement.
        let confirmed = match confirmer {
            Some(c) => {
                let created: Vec<Bytes32> =
                    validated.additions.iter().map(|a| a.coin_id()).collect();
                c.confirm(&created).await.unwrap_or(false)
            }
            None => false,
        };
        Ok(TipSpendOutcome::Broadcast { txid, confirmed })
    }

    /// Point-read live sync (§18.12): refresh the wallet DB from the fallback tier for the wallet's
    /// OWN tracked puzzle hashes — read XCH coins by puzzle hash AND CAT coins by hint (a CAT is
    /// hinted to the owner p2 hash), upsert them, then attribute CATs to their TAIL via the attached
    /// lineage source (so `$DIG` coins gain an `asset_id` and become selectable). Best-effort +
    /// idempotent: it never DELETES rows and re-runs safely, so the spend path selects over CURRENT
    /// chain state without a subscription loop. A no-op with the graceful `EmptyFallback` (empty
    /// reads); a locked wallet (no signer ⇒ no tracked puzzle hashes) is a clean `Ok(0)`. Returns
    /// the number of coin rows upserted.
    pub async fn refresh_tracked_coins(&self) -> Result<usize> {
        let Some(signer) = self.current_signer() else {
            return Ok(0); // locked: no key ⇒ no tracked puzzle hashes to sync
        };
        let phs: Vec<String> = signer.puzzle_hashes().iter().map(hex::encode).collect();
        if phs.is_empty() {
            return Ok(0);
        }
        // Observed BEFORE this refresh writes anything, so a reset landing while it runs makes
        // its latch below a no-op rather than a re-declaration of the emptied replica as
        // authoritative (dig-node#454). Same guard, same counter, as the catch-up path.
        let epoch_at_start = self.db.reset_epoch().await?;
        // XCH coins sitting at our puzzle hashes + CAT coins hinted to them (unspent + recent).
        let mut fetched = self.fallback.coin_records_by_puzzle_hashes(&phs).await?;
        fetched.extend(self.fallback.coin_records_by_hints(&phs).await?);
        let fetched_rows: Vec<CoinRow> = fetched.iter().map(fallback_coin_to_row).collect();

        // A HINT IS A CLAIM, NOT A FACT (dig-node#394). `coin_records_by_hints` finds coins that
        // merely say they are for this wallet, and anybody may `CREATE_COIN` with any hint. These
        // rows carry `asset_id: None`, which in this schema means XCH — so upserting them straight
        // into `coins`, as this path used to, let one mojo per displayed base unit mint a
        // fabricated XCH balance and, since selection is largest-first over a coin nobody can
        // spend, a permanent send kill-switch. No peer required: the coinset oracle serves it.
        //
        // Routed through the SAME staging table as the peer frame path rather than guarded
        // separately. One admission point that demands a lineage proof is the shape; three guards
        // that must agree is what produced this defect at three tiers.
        let owned_hashes: Vec<_> = signer.puzzle_hashes().into_iter().collect();
        let derived = super::cat_discovery::DerivedCats::derive(
            &owned_hashes,
            &[digstore_chain::dig::DIG_ASSET_ID],
        );
        let owned: HashSet<String> = phs.iter().cloned().collect();
        let promoted = self
            .db
            .existing_coin_ids(
                &fetched_rows
                    .iter()
                    .map(|r| r.coin_id.clone())
                    .collect::<Vec<_>>(),
            )
            .await?;
        let (rows, staged) =
            super::cat_discovery::route_point_read_rows(&fetched_rows, &owned, &derived, |id| {
                promoted.contains(id)
            });
        let n = rows.len();
        if n > 0 {
            self.db.upsert_coins(&rows).await?;
        }
        if !staged.is_empty() {
            self.db.stage_cat_admissions(&staged).await?;
        }
        // Attribute CATs (fills `asset_id`/`hint`) when a lineage source is attached — best-effort:
        // an attribution read failure must never make a fresh XCH sync look like a hard error.
        if let Some(lineage) = self.lineage.as_deref() {
            // Promote whatever the CAT staging table can prove (dig-node#380), so a coin
            // discovered at a derived hash becomes spendable on this tier too. Best-effort for
            // the same reason attribution is: a chain-read failure must not make a fresh XCH sync
            // look like a hard error.
            // ONE OF TWO promotion sites. The other is the supervisor's `CatAttributor` on the
            // peer path, which #391 wired into production (dig-node#382) -- until then
            // `CatAttributor` was constructed under `cfg(test)` alone and this was the only site
            // that ran on a shipped node. Both are still needed: this tier promotes on a
            // point-read refresh, the peer tier on the sync that delivers the coin.
            //
            // It must not be silent either way: a `let _ =` discarded both the counts and the
            // cause, so a wallet whose $DIG never appeared produced no evidence of why anywhere.
            //
            // Still best-effort, and deliberately: a chain-read failure must not turn a successful
            // XCH refresh into a hard error.
            match super::cat_discovery::promote_staged_cats(&self.db, lineage, &owned).await {
                Ok(stats) if stats.promoted > 0 || stats.resolved > 0 || stats.refused > 0 => {
                    tracing::info!(
                        promoted = stats.promoted,
                        resolved = stats.resolved,
                        refused = stats.refused,
                        deferred = stats.deferred,
                        "wallet sync: CAT admission promotion pass (point-read tier)"
                    )
                }
                Ok(stats) if stats.deferred > 0 => tracing::debug!(
                    deferred = stats.deferred,
                    "wallet sync: staged CAT coins are awaiting a readable parent spend"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    error = %e,
                    "wallet sync: the CAT promotion pass failed; staged coins are unchanged"
                ),
            }
            let plain: HashSet<String> = phs.iter().cloned().collect();
            let _ =
                singleton::reconstruct_all(&self.db, lineage, &self.config.address_prefix, &plain)
                    .await;
        }
        // Mark the DB synced so wallet-data reads flip from the fallback to the local DB (routing).
        //
        // This is the OTHER writer of `initial_sync_complete` besides
        // [`super::sync::initial_sync_with_authority`] — worth stating, because that function's own note
        // claimed to be the only one. It is outside the peer trust boundary: its rows come from
        // the coinset ORACLE, never from a peer, and its only caller returns early unless
        // live-broadcast is on.
        //
        // It DOES latch over zero rows, though: an oracle that answers an empty set for both
        // reads leaves `n == 0` and the flag set anyway, declaring an empty table authoritative
        // — which now additionally opens the spend gate above over that empty table. The
        // failure mode is a refusal-shaped one (no inputs to select), not a wrong spend, which
        // is why it is recorded rather than changed here; dig_ecosystem#2514 owns it.
        //
        // It cannot arm the ARRIVAL BASELINE, and that is load-bearing rather than incidental
        // (dig_ecosystem#2548). This path has replayed no history, so a baseline armed from it
        // would sit at zero — permanently, because arming is once-per-wallet — and the first live
        // update after the real catch-up would announce the wallet's entire receive history as
        // incoming payments. Arming requires a `CatchUpReplay`, which only the completed
        // address-history catch-up produces; see `WalletDb::complete_catch_up`.
        //
        // It may only latch over the addresses it ACTUALLY FETCHED. `phs` is custody's own set; an
        // externally enrolled key (`control.wallet.watch`) is not in it, so its coins were never
        // requested here — yet the flag is global, and setting it would declare the replica
        // authoritative for those addresses too. That is dig_ecosystem#2871's variant 1b, and it is
        // the PERMANENT form of it: nothing later clears the flag, so a funded enrolled address
        // would answer `balance: 0, synced: true, source: "db"` for the life of the install.
        if self.watchlist_is_covered_by(&phs) {
            // The flag AND the set it was earned over. Latching the flag alone would leave the
            // recorded coverage stale — describing whatever the LAST catch-up ran over, or nothing
            // at all on a replica that never had one — and the read router asks about coverage, so
            // a flag with no matching recording buys this path nothing (dig_ecosystem#2871).
            //
            // `phs` is what this pass actually fetched, so recording it is the honest claim: it
            // covers custody's own addresses, and `watchlist_is_covered_by` above has already
            // established that it covers every enrolled one too.
            if !self
                .db
                .latch_synced_over_unless_reset(&CoveredSet::from_hex(&phs), epoch_at_start)
                .await?
            {
                tracing::info!(concat!(
                    "wallet sync: the coin database was reset while this refresh ran, ",
                    "so its result was discarded rather than used to mark the emptied ",
                    "replica synced"
                ));
            }
        } else {
            tracing::info!(
                "wallet sync: a point-read refresh covered only this node's own custody, so the \
                 replica stays non-authoritative for the externally enrolled addresses it did not \
                 fetch"
            );
        }
        // Incoming-funds arrivals (dig_ecosystem#2548). Run AFTER attribution, so a CAT coin this
        // pass fetched is announced with its asset id rather than held as indeterminate — the
        // direct-peer sync path cannot see CAT coins at all (they sit at a curried puzzle hash,
        // outside the subscribed p2 set), so this is the ONLY path on which a CAT arrival exists.
        //
        // Best-effort, like the attribution above: failing to record an arrival must never turn a
        // successful coin refresh into a hard error, and the next pass re-examines what this one
        // missed.
        let through = rows
            .iter()
            .filter_map(|r| r.created_height)
            .max()
            .unwrap_or(0)
            .max(i64::from(
                self.db.sync_state().await?.peak_height.unwrap_or(0),
            ));
        let _ = self
            .db
            .record_arrivals(&phs, u32::try_from(through).unwrap_or(0))
            .await;
        Ok(n)
    }

    /// The incoming-funds ARRIVALS recorded after cursor position `after_seq`, oldest first
    /// (dig_ecosystem#2548) — what `control.wallet.arrivals` serves.
    ///
    /// A pull, not a push: the control surface is request/response, and inventing a streaming
    /// protocol to carry this would be a three-repo contract change for something a cursor answers.
    /// The cursor is monotonic and persisted, so a client that stores its last `seq` learns about
    /// every arrival exactly once across restarts of either side.
    ///
    /// Returns `(page, latest)`. `latest` is the newest position the ledger holds and is read
    /// AFTER the page, so it may already be ahead of it — which is exactly why a client must resume
    /// from the last row it actually RECEIVED and never from `latest`. `latest` answers only "where
    /// would I be if I skipped to now", the question a first-run client asks so it does not replay
    /// the whole ledger as notifications.
    ///
    /// Reads the local replica ONLY. There is no oracle path here and there must not be: this is
    /// an open, token-less read, and routing it outbound would disclose the wallet's addresses to
    /// a third party on every poll.
    pub async fn wallet_arrivals(
        &self,
        after_seq: i64,
        limit: i64,
    ) -> sqlx::Result<(Vec<super::arrivals::Arrival>, i64)> {
        let page = self.db.arrivals_since(after_seq, limit).await?;
        let latest = self.db.arrival_cursor().await?;
        Ok((page, latest))
    }

    async fn send_xch(&self, req: &SendXch) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let amount = amount_u64(&req.amount)?;
        let fee = amount_u64(&req.fee)?;
        let dest = self.decode_ph(&req.address)?;
        let inputs = spend::select_coins(
            self.spendable_coins(None).await?,
            amount.saturating_add(fee),
        )?;
        let coin_spends =
            spend::build_xch_send(signer, &inputs, dest, amount, fee, self.change_ph()?)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn bulk_send_xch(&self, req: &BulkSendXch) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let amount = amount_u64(&req.amount)?;
        let fee = amount_u64(&req.fee)?;
        let dests = req
            .addresses
            .iter()
            .map(|a| self.decode_ph(a))
            .collect::<Result<Vec<_>>>()?;
        let target = amount
            .saturating_mul(dests.len() as u64)
            .saturating_add(fee);
        let inputs = spend::select_coins(self.spendable_coins(None).await?, target)?;
        let coin_spends =
            spend::build_bulk_xch_send(signer, &inputs, &dests, amount, fee, self.change_ph()?)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn combine(&self, req: &Combine) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let inputs = self.coins_from_ids(&req.coin_ids).await?;
        let coin_spends = spend::build_combine(signer, &inputs, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn split(&self, req: &Split) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let inputs = self.coins_from_ids(&req.coin_ids).await?;
        let coin_spends =
            spend::build_split(signer, &inputs, req.output_count, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn multi_send(&self, req: &MultiSend) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let mut payments = Vec::with_capacity(req.payments.len());
        for p in &req.payments {
            if p.asset_id.is_some() {
                return Err(Error::api(
                    "CAT payments in multi_send are not yet supported (use send_cat)",
                ));
            }
            payments.push(spend::MultiPayment {
                dest: self.decode_ph(&p.address)?,
                amount: amount_u64(&p.amount)?,
            });
        }
        let target = payments
            .iter()
            .map(|p| p.amount)
            .fold(0u64, u64::saturating_add)
            .saturating_add(fee);
        let inputs = spend::select_coins(self.spendable_coins(None).await?, target)?;
        let coin_spends =
            spend::build_multi_send(signer, &inputs, &payments, fee, self.change_ph()?)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    /// Resolve the spendable input `Cat`s covering `amount` of `asset_id`, and the XCH fee
    /// coins covering `fee`, via the attached lineage source.
    ///
    /// Gated on [`Self::require_authoritative_coins`] IN ITS OWN RIGHT, not through the fee
    /// coins: the fee branch is skipped entirely when `fee == 0`, which is the ordinary case and
    /// the unconditional one for offers.
    async fn select_cats(
        &self,
        asset_id: &str,
        amount: u64,
        fee: u64,
    ) -> Result<(Vec<chia_wallet_sdk::driver::Cat>, Vec<Coin>)> {
        // FIRST, ahead of the lineage lookup: an unauthoritative replica must be refused for
        // being unauthoritative, whatever else is or is not attached to this backend.
        self.require_authoritative_coins().await?;
        let lineage = self
            .lineage
            .as_deref()
            .ok_or_else(|| Error::internal("CAT send requires a lineage source"))?;
        // The unreserved set, for the same reason as `spendable_coins` (dig_ecosystem#2763): a CAT
        // coin committed to an in-flight bundle must not be selected into a second one.
        self.db
            .prune_reservations(super::custody::now_ms() as i64)
            .await?;
        let rows = select_cat_rows(
            self.db.unreserved_unspent_coins(Some(asset_id)).await?,
            amount,
        )?;
        let mut cats = Vec::with_capacity(rows.len());
        for row in &rows {
            let created = row
                .created_height
                .ok_or_else(|| Error::internal("CAT coin missing created height"))?
                as u32;
            let parent = lineage
                .parent_spend(&row.parent_coin_info, created)
                .await?
                .found()
                .ok_or_else(|| Error::internal("CAT parent spend unavailable"))?;
            let child = singleton::coin_from_row(row)?;
            let cat = singleton::resolve_cat(&parent, child)?
                .ok_or_else(|| Error::internal("could not resolve CAT lineage"))?;
            cats.push(cat);
        }
        let xch_fee_coins = if fee > 0 {
            spend::select_coins(self.spendable_coins(None).await?, fee)?
        } else {
            Vec::new()
        };
        Ok((cats, xch_fee_coins))
    }

    async fn send_cat(&self, req: &SendCat) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let amount = amount_u64(&req.amount)?;
        let fee = amount_u64(&req.fee)?;
        let dest = self.decode_ph(&req.address)?;
        let (cats, xch_fee_coins) = self.select_cats(&req.asset_id, amount, fee).await?;
        let coin_spends = spend::build_cat_send(
            signer,
            &cats,
            dest,
            amount,
            self.change_ph()?,
            req.include_hint,
            fee,
            &xch_fee_coins,
        )?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn bulk_send_cat(&self, req: &BulkSendCat) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let amount = amount_u64(&req.amount)?;
        let fee = amount_u64(&req.fee)?;
        let outputs = req
            .addresses
            .iter()
            .map(|a| self.decode_ph(a).map(|ph| (ph, amount)))
            .collect::<Result<Vec<_>>>()?;
        let total = amount.saturating_mul(req.addresses.len() as u64);
        let (cats, xch_fee_coins) = self.select_cats(&req.asset_id, total, fee).await?;
        let coin_spends = spend::build_cat_send_multi(
            signer,
            &cats,
            &outputs,
            self.change_ph()?,
            req.include_hint,
            fee,
            &xch_fee_coins,
        )?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn sign_coin_spends(&self, req: &SignCoinSpends) -> Result<SignCoinSpendsResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let coin_spends = req
            .coin_spends
            .iter()
            .map(spend::coin_spend_from_json)
            .collect::<Result<Vec<_>>>()?;
        let signature = signer.sign(&coin_spends)?;
        let bundle = SpendBundle::new(coin_spends, signature);
        if req.auto_submit {
            if let Some(bc) = self.broadcaster.as_ref() {
                bc.broadcast(&bundle).await?;
            }
        }
        Ok(SignCoinSpendsResponse {
            spend_bundle: spend::spend_bundle_to_json(&bundle)?,
        })
    }

    async fn view_coin_spends(&self, req: &ViewCoinSpends) -> Result<ViewCoinSpendsResponse> {
        let coin_spends = req
            .coin_spends
            .iter()
            .map(spend::coin_spend_from_json)
            .collect::<Result<Vec<_>>>()?;
        let summary = spend::summarize(
            &coin_spends,
            &self.config.address_prefix,
            &self.wallet_puzzle_hashes(),
        )?;
        Ok(ViewCoinSpendsResponse { summary })
    }

    async fn submit_transaction(
        &self,
        req: &SubmitTransaction,
    ) -> Result<SubmitTransactionResponse> {
        let bundle = spend::spend_bundle_from_json(&req.spend_bundle)?;
        // Fail-closed: structural + CLVM validation before broadcast.
        spend::run_and_validate(&bundle.coin_spends)?;
        let bc = self
            .broadcaster
            .as_ref()
            .ok_or_else(|| Error::internal("no broadcaster configured"))?;
        bc.broadcast(&bundle).await?;
        Ok(SubmitTransactionResponse {})
    }

    // ---- offer suite + DID/NFT mint & transfer (#218) --------------------

    /// The lineage source, or an error when none is attached — CAT/singleton spends need
    /// parent-spend reads to reconstruct their spendable driver objects.
    fn require_lineage(&self) -> Result<&dyn LineageSource> {
        self.lineage
            .as_deref()
            .ok_or_else(|| Error::internal("this operation requires a lineage source"))
    }

    /// Resolve a coin's parent spend + the current coin, from the wallet DB + lineage — the
    /// input a singleton (NFT/DID/option) spend reconstruction needs.
    ///
    /// Gated on [`Self::require_authoritative_coins`]: this is the ONE reader every singleton
    /// spend resolves its input coin through ([`Self::nft_parent_child`],
    /// [`Self::did_parent_child`], [`Self::option_parent_child`] all delegate here), so gating
    /// it covers all three rather than three sites that can drift apart.
    async fn singleton_parent_child(&self, coin_id: &str) -> Result<(ParentSpend, Coin)> {
        self.require_authoritative_coins().await?;
        let lineage = self.require_lineage()?;
        let row = self
            .db
            .coins_by_ids(&[coin_id.to_string()])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::not_found("coin not tracked in the wallet"))?;
        let created =
            row.created_height
                .ok_or_else(|| Error::internal("coin missing created height"))? as u32;
        let parent = lineage
            .parent_spend(&row.parent_coin_info, created)
            .await?
            .found()
            .ok_or_else(|| Error::internal("parent spend unavailable"))?;
        let child = singleton::coin_from_row(&row)?;
        Ok((parent, child))
    }

    /// Resolve `nft_id` (hex/bech32m) to its current coin's (parent spend, coin).
    async fn nft_parent_child(&self, nft_id: &str) -> Result<(ParentSpend, Coin)> {
        let launcher = normalize_singleton_id(nft_id);
        let row = self
            .db
            .nft(&launcher)
            .await?
            .ok_or_else(|| Error::not_found("NFT not tracked in the wallet"))?;
        self.singleton_parent_child(&row.coin_id).await
    }

    /// Resolve `did_id` (hex/bech32m) to its current coin's (parent spend, coin).
    async fn did_parent_child(&self, did_id: &str) -> Result<(ParentSpend, Coin)> {
        let launcher = normalize_singleton_id(did_id);
        let row = self
            .db
            .all_dids()
            .await?
            .into_iter()
            .find(|d| d.launcher_id == launcher)
            .ok_or_else(|| Error::not_found("DID not tracked in the wallet"))?;
        self.singleton_parent_child(&row.coin_id).await
    }

    /// Reconstruct the spendable [`chia_wallet_sdk::driver::Did`] for `did_id` (a simple DID's
    /// metadata is `NIL`, so it is safe to hand to the mint builder's own context).
    async fn resolve_did(&self, did_id: &str) -> Result<chia_wallet_sdk::driver::Did> {
        let (parent, child) = self.did_parent_child(did_id).await?;
        let mut ctx = chia_wallet_sdk::driver::SpendContext::new();
        singleton::parse_did_in(&mut ctx, &parent, child)?
            .ok_or_else(|| Error::internal("could not reconstruct the minting DID"))
    }

    /// The spendable CAT coins of `asset_id` covering `amount` (with lineage proofs).
    async fn resolve_offer_cats(&self, asset_id: &str, amount: u64) -> Result<Vec<Cat>> {
        let (cats, _fee) = self.select_cats(asset_id, amount, 0).await?;
        Ok(cats)
    }

    async fn make_offer(&self, req: &MakeOffer) -> Result<MakeOfferResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let receive_ph = match &req.receive_address {
            Some(a) => self.decode_ph(a)?,
            None => self.change_ph()?,
        };
        let change = self.change_ph()?;

        let mut inputs = offers::OfferInputs::default();
        let mut offered_legs = Vec::with_capacity(req.offered_assets.len());
        let mut any_xch_offered = false;
        for a in &req.offered_assets {
            let amount = amount_u64(&a.amount)?;
            match &a.asset_id {
                None => any_xch_offered = true,
                Some(id) => inputs
                    .cats
                    .extend(self.resolve_offer_cats(id, amount).await?),
            }
            offered_legs.push(offers::OfferLeg {
                asset_id: opt_asset_id(&a.asset_id)?,
                amount,
            });
        }
        if any_xch_offered {
            inputs.xch = self.spendable_coins(None).await?;
        }
        let requested_legs = req
            .requested_assets
            .iter()
            .map(|a| {
                Ok(offers::OfferLeg {
                    asset_id: opt_asset_id(&a.asset_id)?,
                    amount: amount_u64(&a.amount)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let (offer_str, offer_id) = offers::build_make_offer(
            signer,
            &inputs,
            &offered_legs,
            &requested_legs,
            receive_ph,
            change,
            fee,
        )?;

        if req.auto_import {
            let summary = offers::summarize_offer(&offer_str)?;
            self.db
                .upsert_offer(&OfferDbRow {
                    offer_id: offer_id.clone(),
                    offer: offer_str.clone(),
                    status: "active".into(),
                    creation_timestamp: now_secs() as i64,
                    summary_json: serde_json::to_string(&summary).unwrap_or_default(),
                })
                .await?;
        }
        Ok(MakeOfferResponse {
            offer: offer_str,
            offer_id,
        })
    }

    async fn take_offer(&self, req: &TakeOffer) -> Result<TakeOfferResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let change = self.change_ph()?;

        // The taker pays the maker's requested assets — fund exactly those.
        let summary = offers::summarize_offer(&req.offer)?;
        let mut inputs = offers::OfferInputs::default();
        let mut need_xch = fee > 0;
        for a in &summary.taker {
            let amount = a.amount.to_u64().unwrap_or(0);
            match &a.asset.asset_id {
                None => need_xch = true,
                Some(id) => inputs
                    .cats
                    .extend(self.resolve_offer_cats(id, amount).await?),
            }
        }
        if need_xch {
            inputs.xch = self.spendable_coins(None).await?;
        }

        let bundle = offers::build_take_offer(signer, &req.offer, &inputs, change, fee)?;
        spend::run_and_validate(&bundle.coin_spends)?;
        let tx_summary = spend::summarize(
            &bundle.coin_spends,
            &self.config.address_prefix,
            &self.wallet_puzzle_hashes(),
        )?;
        if req.auto_submit {
            if let Some(bc) = self.broadcaster.as_ref() {
                bc.broadcast(&bundle).await?;
            }
        }
        Ok(TakeOfferResponse {
            summary: tx_summary,
            spend_bundle: spend::spend_bundle_to_json(&bundle)?,
            transaction_id: offers::offer_id(&req.offer)?,
        })
    }

    fn view_offer_summary(&self, req: &ViewOffer) -> Result<OfferSummary> {
        offers::summarize_offer(&req.offer)
    }

    async fn view_offer(&self, req: &ViewOffer) -> Result<ViewOfferResponse> {
        let summary = self.view_offer_summary(req)?;
        let offer_id = offers::offer_id(&req.offer)?;
        let status = match self.db.offer(&offer_id).await? {
            Some(r) => parse_offer_status(&r.status),
            None => OfferRecordStatus::Active,
        };
        Ok(ViewOfferResponse {
            offer: summary,
            status,
        })
    }

    fn combine_offers(&self, req: &CombineOffers) -> Result<CombineOffersResponse> {
        Ok(CombineOffersResponse {
            offer: offers::combine_offers(&req.offers)?,
        })
    }

    async fn get_offers(&self) -> Result<GetOffersResponse> {
        let rows = self.db.all_offers().await?;
        Ok(GetOffersResponse {
            offers: rows.iter().filter_map(offer_row_to_record).collect(),
        })
    }

    async fn get_offer(&self, req: &GetOffer) -> Result<GetOfferResponse> {
        let row = self
            .db
            .offer(&req.offer_id)
            .await?
            .ok_or_else(|| Error::not_found("offer not found"))?;
        Ok(GetOfferResponse {
            offer: offer_row_to_record(&row)
                .ok_or_else(|| Error::internal("corrupt stored offer record"))?,
        })
    }

    async fn cancel_offer(&self, req: &CancelOffer) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let change = self.change_ph()?;
        let row = self
            .db
            .offer(&req.offer_id)
            .await?
            .ok_or_else(|| Error::not_found("offer not found"))?;
        let coin_spends = offers::build_cancel_offer(signer, &row.offer, change, fee)?;
        let resp = self.finalize_spend(coin_spends, req.auto_submit).await?;
        self.db.set_offer_status(&req.offer_id, "cancelled").await?;
        Ok(resp)
    }

    async fn create_did(&self, req: &CreateDid) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let inputs =
            spend::select_coins(self.spendable_coins(None).await?, 1u64.saturating_add(fee))?;
        let (coin_spends, _launcher) =
            mint::build_create_did(signer, &inputs, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn bulk_mint_nfts(&self, req: &BulkMintNfts) -> Result<BulkMintNftsResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let did = self.resolve_did(&req.did_id).await?;
        let default_owner = self.change_ph()?;
        let mut plans = Vec::with_capacity(req.mints.len());
        for m in &req.mints {
            let owner_ph = match &m.address {
                Some(a) => self.decode_ph(a)?,
                None => default_owner,
            };
            let royalty_ph = match &m.royalty_address {
                Some(a) => self.decode_ph(a)?,
                None => owner_ph,
            };
            let metadata = mint::nft_metadata(
                m.data_uris.clone(),
                m.data_hash.as_deref(),
                m.metadata_uris.clone(),
                m.metadata_hash.as_deref(),
                m.license_uris.clone(),
                m.license_hash.as_deref(),
                m.edition_number,
                m.edition_total,
            )?;
            plans.push(mint::NftMintPlan {
                metadata,
                owner_ph,
                royalty_ph,
                royalty_basis_points: m.royalty_ten_thousandths,
            });
        }
        let n = plans.len() as u64;
        let funding =
            spend::select_coins(self.spendable_coins(None).await?, n.saturating_add(fee))?;
        let (coin_spends, launcher_ids) =
            mint::build_bulk_mint(signer, did, &plans, &funding, self.change_ph()?, fee)?;
        spend::run_and_validate(&coin_spends)?;
        let summary = spend::summarize(
            &coin_spends,
            &self.config.address_prefix,
            &self.wallet_puzzle_hashes(),
        )?;
        if req.auto_submit {
            if let (Some(s), Some(bc)) = (self.current_signer(), self.broadcaster.as_ref()) {
                let sig = s.sign(&coin_spends)?;
                bc.broadcast(&SpendBundle::new(coin_spends.clone(), sig))
                    .await?;
            }
        }
        let coin_spends_json = coin_spends
            .iter()
            .map(spend::coin_spend_to_json)
            .collect::<Result<Vec<_>>>()?;
        Ok(BulkMintNftsResponse {
            nft_ids: launcher_ids.iter().map(hex::encode).collect(),
            summary,
            coin_spends: coin_spends_json,
        })
    }

    async fn transfer_nfts(&self, req: &TransferNfts) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let dest = self.decode_ph(&req.address)?;
        let mut nfts = Vec::with_capacity(req.nft_ids.len());
        for id in &req.nft_ids {
            nfts.push(self.nft_parent_child(id).await?);
        }
        let fee_coins = if fee > 0 {
            spend::select_coins(self.spendable_coins(None).await?, fee)?
        } else {
            Vec::new()
        };
        let coin_spends =
            mint::build_nft_transfer(signer, &nfts, dest, &fee_coins, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn transfer_dids(&self, req: &TransferDids) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let dest = self.decode_ph(&req.address)?;
        let mut dids = Vec::with_capacity(req.did_ids.len());
        for id in &req.did_ids {
            dids.push(self.did_parent_child(id).await?);
        }
        let fee_coins = if fee > 0 {
            spend::select_coins(self.spendable_coins(None).await?, fee)?
        } else {
            Vec::new()
        };
        let coin_spends =
            mint::build_did_transfer(signer, &dids, dest, &fee_coins, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    // ---- options (#205 PR4) -----------------------------------------------

    /// Resolve `option_id` (hex/bech32m) to its current coin's (parent spend, coin).
    async fn option_parent_child(&self, option_id: &str) -> Result<(ParentSpend, Coin)> {
        let launcher = normalize_singleton_id(option_id);
        let row = self
            .db
            .option(&launcher)
            .await?
            .ok_or_else(|| Error::not_found("option not tracked in the wallet"))?;
        self.singleton_parent_child(&row.coin_id).await
    }

    async fn get_options(&self, req: &GetOptions) -> Result<GetOptionsResponse> {
        let rows = self.db.all_options().await?;
        let mut all: Vec<OptionRecord> = rows
            .iter()
            .filter(|r| req.include_hidden || r.visible)
            .filter_map(|r| options::record_from_row(r, &self.address_of(&r.p2_puzzle_hash)))
            .collect();
        all.sort_by(|a, b| {
            let ord = match req.sort_mode {
                // Fall back to a stable id ordering when neither side has a name set.
                OptionSortMode::Name => a
                    .name
                    .cmp(&b.name)
                    .then_with(|| a.launcher_id.cmp(&b.launcher_id)),
                OptionSortMode::Recent => b.created_height.cmp(&a.created_height),
            };
            if req.ascending {
                ord
            } else {
                ord.reverse()
            }
        });
        let total = all.len() as u32;
        let page = all
            .into_iter()
            .skip(req.offset as usize)
            .take(req.limit as usize)
            .collect();
        Ok(GetOptionsResponse {
            options: page,
            total,
        })
    }

    async fn get_option(&self, req: &GetOption) -> Result<GetOptionResponse> {
        let id = normalize_singleton_id(&req.option_id);
        let option = match self.db.option(&id).await? {
            Some(row) => options::record_from_row(&row, &self.address_of(&row.p2_puzzle_hash)),
            None => None,
        };
        Ok(GetOptionResponse { option })
    }

    async fn mint_option(&self, req: &MintOption) -> Result<MintOptionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        if req.underlying.asset_id.is_some() {
            return Err(Error::api(
                "mint_option: only an XCH underlying is supported in this backend (see \
                 crate::sage::options module docs)",
            ));
        }
        let underlying_amount = amount_u64(&req.underlying.amount)?;
        let strike = options::strike_type_from_asset(&req.strike)?;
        let owner_ph = self.change_ph()?;

        let all_spendable = self.spendable_coins(None).await?;
        let underlying_inputs = spend::select_coins(all_spendable.clone(), underlying_amount)?;
        let underlying_ids: HashSet<Bytes32> =
            underlying_inputs.iter().map(|c| c.coin_id()).collect();
        let remaining: Vec<Coin> = all_spendable
            .into_iter()
            .filter(|c| !underlying_ids.contains(&c.coin_id()))
            .collect();
        let launcher_inputs = spend::select_coins(remaining, 1u64.saturating_add(fee))?;

        let (coin_spends, info) = options::build_mint_option(
            signer,
            &underlying_inputs,
            underlying_amount,
            &launcher_inputs,
            strike,
            req.expiration_seconds,
            owner_ph,
            owner_ph,
            fee,
        )?;
        spend::run_and_validate(&coin_spends)?;
        let summary = spend::summarize(
            &coin_spends,
            &self.config.address_prefix,
            &self.wallet_puzzle_hashes(),
        )?;

        let option_id = hex::encode(info.launcher_id);
        let strike_amount = amount_u64(&req.strike.amount)?;
        let underlying_coin_hex = hex::encode(info.underlying_coin_id);
        let p2_hex = hex::encode(info.p2_puzzle_hash);
        let record = options::new_record(
            &option_id,
            &option_id,
            &self.address_of(&p2_hex),
            1,
            options::asset_for(None), // this backend mints XCH-underlying options only
            underlying_amount,
            &underlying_coin_hex,
            options::asset_for(req.strike.asset_id.as_deref()),
            strike_amount,
            req.expiration_seconds,
        );
        self.db
            .upsert_option(&OptionDbRow {
                option_id: option_id.clone(),
                coin_id: option_id.clone(),
                underlying_coin_id: underlying_coin_hex,
                underlying_delegated_puzzle_hash: hex::encode(
                    info.underlying_delegated_puzzle_hash,
                ),
                p2_puzzle_hash: p2_hex,
                visible: true,
                created_height: None,
                record_json: serde_json::to_string(&record).unwrap_or_default(),
            })
            .await?;

        if req.auto_submit {
            if let (Some(s), Some(bc)) = (self.current_signer(), self.broadcaster.as_ref()) {
                let sig = s.sign(&coin_spends)?;
                bc.broadcast(&SpendBundle::new(coin_spends.clone(), sig))
                    .await?;
            }
        }
        let coin_spends_json = coin_spends
            .iter()
            .map(spend::coin_spend_to_json)
            .collect::<Result<Vec<_>>>()?;
        Ok(MintOptionResponse {
            option_id,
            summary,
            coin_spends: coin_spends_json,
        })
    }

    async fn transfer_options(&self, req: &TransferOptions) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let signer = signer.as_ref();
        let fee = amount_u64(&req.fee)?;
        let dest = self.decode_ph(&req.address)?;
        let mut opts = Vec::with_capacity(req.option_ids.len());
        for id in &req.option_ids {
            opts.push(self.option_parent_child(id).await?);
        }
        let fee_coins = if fee > 0 {
            spend::select_coins(self.spendable_coins(None).await?, fee)?
        } else {
            Vec::new()
        };
        let coin_spends = options::build_option_transfer(
            signer,
            &opts,
            dest,
            &fee_coins,
            self.change_ph()?,
            fee,
        )?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    /// `exercise_options` — a documented follow-on; see `crate::sage::options` module docs.
    async fn exercise_options(&self, _req: &ExerciseOptions) -> Result<TransactionResponse> {
        Err(options::exercise_options_unimplemented())
    }

    // ---- record-update actions (#205 PR4) ----------------------------------

    async fn resync_cat(&self, req: &ResyncCat) -> Result<ActionResponse> {
        actions::resync_cat(&self.db, &req.asset_id).await?;
        Ok(ActionResponse {})
    }

    async fn update_cat(&self, req: &UpdateCat) -> Result<ActionResponse> {
        actions::update_cat(&self.db, &req.record).await?;
        Ok(ActionResponse {})
    }

    async fn update_did_action(&self, req: &UpdateDid) -> Result<ActionResponse> {
        let id = normalize_singleton_id(&req.did_id);
        actions::update_did(&self.db, &id, req.name.as_deref(), req.visible).await?;
        Ok(ActionResponse {})
    }

    async fn update_option_action(&self, req: &UpdateOption) -> Result<ActionResponse> {
        let id = normalize_singleton_id(&req.option_id);
        actions::update_option(&self.db, &id, req.visible).await?;
        Ok(ActionResponse {})
    }

    async fn update_nft_action(&self, req: &UpdateNft) -> Result<ActionResponse> {
        let id = normalize_singleton_id(&req.nft_id);
        actions::update_nft(&self.db, &id, req.visible).await?;
        Ok(ActionResponse {})
    }

    async fn update_nft_collection_action(
        &self,
        req: &UpdateNftCollection,
    ) -> Result<ActionResponse> {
        actions::update_nft_collection(&self.db, &req.collection_id, req.visible).await?;
        Ok(ActionResponse {})
    }

    async fn redownload_nft_action(&self, req: &RedownloadNft) -> Result<ActionResponse> {
        let id = normalize_singleton_id(&req.nft_id);
        actions::redownload_nft(&self.db, &id).await?;
        Ok(ActionResponse {})
    }

    /// Raise the HD derivation floor, reporting the floors in force afterwards (dig-node#256).
    ///
    /// The one action method that does NOT return the shared empty response, because its no-op is
    /// reachable and costs money: see [`IncreaseDerivationIndexResponse`].
    async fn increase_derivation_index(
        &self,
        req: &IncreaseDerivationIndex,
    ) -> Result<IncreaseDerivationIndexResponse> {
        actions::increase_derivation_index(&self.db, req.hardened, req.unhardened, req.index).await
    }

    // ---- themes (#205 PR4) --------------------------------------------------

    async fn get_user_themes(&self) -> Result<GetUserThemesResponse> {
        Ok(GetUserThemesResponse {
            themes: themes::get_user_themes(&self.db).await?,
        })
    }

    async fn get_user_theme(&self, req: &GetUserTheme) -> Result<GetUserThemeResponse> {
        Ok(GetUserThemeResponse {
            theme: themes::get_user_theme(&self.db, &req.nft_id).await?,
        })
    }

    async fn save_user_theme(&self, req: &SaveUserTheme) -> Result<ActionResponse> {
        themes::save_user_theme(&self.db, &req.nft_id).await?;
        Ok(ActionResponse {})
    }

    async fn delete_user_theme(&self, req: &DeleteUserTheme) -> Result<ActionResponse> {
        themes::delete_user_theme(&self.db, &req.nft_id).await?;
        Ok(ActionResponse {})
    }

    // ---- network / peers / settings (#205 PR4) -------------------------------

    /// Public so the node's `control.chiaPeers.*` surface reads the SAME peer store the wallet
    /// replica consults. A second reader would let the trusted set and the consulted set drift.
    pub async fn get_peers(&self) -> Result<GetPeersResponse> {
        Ok(GetPeersResponse {
            peers: network::get_peers(&self.db).await?,
        })
    }

    /// The ONE writer of the trusted-peer set, and the only way to reach
    /// [`crate::sage::sync::PeerTrust::Operator`].
    ///
    /// Returns whether the peer ended up TRUSTED, which is not the same as whether the call
    /// succeeded: adding a peer that was BANNED un-bans it without conferring the corroboration
    /// bypass. `control.chiaPeers.add` reports that distinction, so it dispatches here rather than
    /// through the Sage-parity wrapper below, which can only say "it worked".
    pub async fn add_peer_reporting_trust(&self, req: &AddPeer) -> Result<bool> {
        network::add_peer(&self.db, &req.ip).await
    }

    /// The ONE remover of the trusted-peer set — see [`WalletBackend::add_peer_reporting_trust`].
    ///
    /// Returns whether an entry MATCHED the address. This is the only way to un-trust a peer that
    /// is believed without corroboration, so the caller must be able to distinguish "it is gone"
    /// from "nothing was there and your peer is still trusted".
    pub async fn remove_peer_reporting_match(&self, req: &RemovePeer) -> Result<bool> {
        network::remove_peer(&self.db, &req.ip, req.ban).await
    }

    /// `add_peer` in the Sage-parity shape, which carries no detail. Prefer
    /// [`WalletBackend::add_peer_reporting_trust`] anywhere the resulting trust state matters.
    pub async fn add_peer(&self, req: &AddPeer) -> Result<ActionResponse> {
        self.add_peer_reporting_trust(req).await?;
        Ok(ActionResponse {})
    }

    /// `remove_peer` in the Sage-parity shape, which carries no detail. Prefer
    /// [`WalletBackend::remove_peer_reporting_match`] anywhere the outcome matters.
    pub async fn remove_peer(&self, req: &RemovePeer) -> Result<ActionResponse> {
        self.remove_peer_reporting_match(req).await?;
        Ok(ActionResponse {})
    }

    async fn set_discover_peers(&self, req: &SetDiscoverPeers) -> Result<ActionResponse> {
        network::set_discover_peers(&self.db, req.discover_peers).await?;
        Ok(ActionResponse {})
    }

    async fn set_target_peers(&self, req: &SetTargetPeers) -> Result<ActionResponse> {
        network::set_target_peers(&self.db, req.target_peers).await?;
        Ok(ActionResponse {})
    }

    async fn set_network(&self, req: &SetNetwork) -> Result<ActionResponse> {
        network::set_network(&self.db, Some(&req.name)).await?;
        Ok(ActionResponse {})
    }

    async fn set_network_override(&self, req: &SetNetworkOverride) -> Result<ActionResponse> {
        network::set_network(&self.db, req.name.as_deref()).await?;
        Ok(ActionResponse {})
    }

    fn get_networks(&self) -> NetworkList {
        network::get_networks()
    }

    async fn get_network(&self) -> Result<GetNetworkResponse> {
        let (net, kind) = network::get_network(&self.db, &self.config.network_id).await?;
        Ok(GetNetworkResponse { network: net, kind })
    }

    async fn set_delta_sync(&self, req: &SetDeltaSync) -> Result<ActionResponse> {
        network::set_delta_sync(&self.db, req.delta_sync).await?;
        Ok(ActionResponse {})
    }

    async fn set_delta_sync_override(&self, req: &SetDeltaSyncOverride) -> Result<ActionResponse> {
        network::set_delta_sync_override(&self.db, req.delta_sync).await?;
        Ok(ActionResponse {})
    }

    async fn set_change_address(&self, req: &SetChangeAddress) -> Result<ActionResponse> {
        network::set_change_address(&self.db, req.change_address.as_deref()).await?;
        Ok(ActionResponse {})
    }

    // ---- the single dispatch both transports call ------------------------

    /// Parse + route a single Sage-parity RPC call. Returns `(http_status, body)`:
    /// success → `200` + the response JSON; error → Sage's status (A.3) + the plain
    /// message. This is the ONE handler set both transports share (design C.3), so their
    /// bodies are byte-identical.
    pub async fn dispatch(&self, method: &str, body: &str) -> (u16, String) {
        if is_signing_method(method) {
            // SERIALIZE signing dispatch: it reads `current_signer` several times.
            let _sign_lock = self.sign_lock.lock().await;
            match self.dispatch_inner(method, body).await {
                Ok(json) => (200, json),
                Err(e) => (e.kind.status(), e.message),
            }
        } else {
            match self.dispatch_inner(method, body).await {
                Ok(json) => (200, json),
                Err(e) => (e.kind.status(), e.message),
            }
        }
    }

    async fn dispatch_inner(&self, method: &str, body: &str) -> Result<String> {
        // Parse the request struct for `method` (empty-body methods ignore `body`).
        macro_rules! req {
            ($ty:ty) => {{
                let body = if body.trim().is_empty() { "{}" } else { body };
                serde_json::from_str::<$ty>(body)
                    .map_err(|e| Error::api(format!("invalid request for {method}: {e}")))?
            }};
        }

        let value: Value = match method {
            "login" => {
                let r = req!(Login);
                json(self.login(&r))?
            }
            "logout" => {
                let _r = req!(Logout);
                json(self.logout())?
            }
            "get_version" => {
                let _r = req!(GetVersion);
                json(self.get_version())?
            }
            "get_sync_status" => {
                let _r = req!(GetSyncStatus);
                json(self.get_sync_status().await?)?
            }
            "check_address" => {
                let r = req!(CheckAddress);
                json(self.check_address(&r))?
            }
            "get_derivations" => {
                let r = req!(GetDerivations);
                json(self.get_derivations(&r).await?)?
            }
            "get_are_coins_spendable" => {
                let r = req!(GetAreCoinsSpendable);
                json(self.get_are_coins_spendable(&r).await?)?
            }
            "get_spendable_coin_count" => {
                let r = req!(GetSpendableCoinCount);
                json(self.get_spendable_coin_count(&r).await?)?
            }
            "get_coins" => {
                let r = req!(GetCoins);
                json(self.get_coins(&r).await?)?
            }
            "get_coins_by_ids" => {
                let r = req!(GetCoinsByIds);
                json(self.get_coins_by_ids(&r).await?)?
            }
            "get_cats" => {
                let _r = req!(GetCats);
                json(self.get_cats().await?)?
            }
            "get_all_cats" => {
                let _r = req!(GetAllCats);
                json(self.get_all_cats().await?)?
            }
            "get_token" => {
                let r = req!(GetToken);
                json(self.get_token(&r).await?)?
            }
            "get_dids" => {
                let _r = req!(GetDids);
                json(self.get_dids().await?)?
            }
            "get_nfts" => {
                let r = req!(GetNfts);
                json(self.get_nfts(&r).await?)?
            }
            "get_nft" => {
                let r = req!(GetNft);
                json(self.get_nft(&r).await?)?
            }
            "get_nft_data" => {
                let r = req!(GetNftData);
                json(self.get_nft_data(&r).await?)?
            }
            "get_nft_collections" => {
                let r = req!(GetNftCollections);
                json(self.get_nft_collections(&r).await?)?
            }
            "get_nft_collection" => {
                let r = req!(GetNftCollection);
                json(self.get_nft_collection(&r).await?)?
            }
            "get_transactions" => {
                let r = req!(GetTransactions);
                json(self.get_transactions(&r).await?)?
            }
            "get_transaction" => {
                let r = req!(GetTransaction);
                json(self.get_transaction(&r).await?)?
            }
            "get_pending_transactions" => {
                let _r = req!(GetPendingTransactions);
                json(self.get_pending_transactions().await?)?
            }
            "is_asset_owned" => {
                let r = req!(IsAssetOwned);
                json(self.is_asset_owned(&r).await?)?
            }
            "get_key" => {
                let r = req!(GetKey);
                json(self.get_key(&r))?
            }
            "get_keys" => {
                let _r = req!(GetKeys);
                json(self.get_keys())?
            }
            "send_xch" => {
                let r = req!(SendXch);
                json(self.send_xch(&r).await?)?
            }
            "bulk_send_xch" => {
                let r = req!(BulkSendXch);
                json(self.bulk_send_xch(&r).await?)?
            }
            "send_cat" => {
                let r = req!(SendCat);
                json(self.send_cat(&r).await?)?
            }
            "bulk_send_cat" => {
                let r = req!(BulkSendCat);
                json(self.bulk_send_cat(&r).await?)?
            }
            "combine" => {
                let r = req!(Combine);
                json(self.combine(&r).await?)?
            }
            "split" => {
                let r = req!(Split);
                json(self.split(&r).await?)?
            }
            "multi_send" => {
                let r = req!(MultiSend);
                json(self.multi_send(&r).await?)?
            }
            "sign_coin_spends" => {
                let r = req!(SignCoinSpends);
                json(self.sign_coin_spends(&r).await?)?
            }
            "view_coin_spends" => {
                let r = req!(ViewCoinSpends);
                json(self.view_coin_spends(&r).await?)?
            }
            "submit_transaction" => {
                let r = req!(SubmitTransaction);
                json(self.submit_transaction(&r).await?)?
            }
            "make_offer" => {
                let r = req!(MakeOffer);
                json(self.make_offer(&r).await?)?
            }
            "take_offer" => {
                let r = req!(TakeOffer);
                json(self.take_offer(&r).await?)?
            }
            "view_offer" => {
                let r = req!(ViewOffer);
                json(self.view_offer(&r).await?)?
            }
            "combine_offers" => {
                let r = req!(CombineOffers);
                json(self.combine_offers(&r)?)?
            }
            "get_offers" => {
                let _r = req!(GetOffers);
                json(self.get_offers().await?)?
            }
            "get_offer" => {
                let r = req!(GetOffer);
                json(self.get_offer(&r).await?)?
            }
            "cancel_offer" => {
                let r = req!(CancelOffer);
                json(self.cancel_offer(&r).await?)?
            }
            "create_did" => {
                let r = req!(CreateDid);
                json(self.create_did(&r).await?)?
            }
            "bulk_mint_nfts" => {
                let r = req!(BulkMintNfts);
                json(self.bulk_mint_nfts(&r).await?)?
            }
            "transfer_nfts" => {
                let r = req!(TransferNfts);
                json(self.transfer_nfts(&r).await?)?
            }
            "transfer_dids" => {
                let r = req!(TransferDids);
                json(self.transfer_dids(&r).await?)?
            }
            "get_options" => {
                let r = req!(GetOptions);
                json(self.get_options(&r).await?)?
            }
            "get_option" => {
                let r = req!(GetOption);
                json(self.get_option(&r).await?)?
            }
            "mint_option" => {
                let r = req!(MintOption);
                json(self.mint_option(&r).await?)?
            }
            "transfer_options" => {
                let r = req!(TransferOptions);
                json(self.transfer_options(&r).await?)?
            }
            "exercise_options" => {
                let r = req!(ExerciseOptions);
                json(self.exercise_options(&r).await?)?
            }
            "resync_cat" => {
                let r = req!(ResyncCat);
                json(self.resync_cat(&r).await?)?
            }
            "update_cat" => {
                let r = req!(UpdateCat);
                json(self.update_cat(&r).await?)?
            }
            "update_did" => {
                let r = req!(UpdateDid);
                json(self.update_did_action(&r).await?)?
            }
            "update_option" => {
                let r = req!(UpdateOption);
                json(self.update_option_action(&r).await?)?
            }
            "update_nft" => {
                let r = req!(UpdateNft);
                json(self.update_nft_action(&r).await?)?
            }
            "update_nft_collection" => {
                let r = req!(UpdateNftCollection);
                json(self.update_nft_collection_action(&r).await?)?
            }
            "redownload_nft" => {
                let r = req!(RedownloadNft);
                json(self.redownload_nft_action(&r).await?)?
            }
            "increase_derivation_index" => {
                let r = req!(IncreaseDerivationIndex);
                json(self.increase_derivation_index(&r).await?)?
            }
            "get_user_themes" => {
                let _r = req!(GetUserThemes);
                json(self.get_user_themes().await?)?
            }
            "get_user_theme" => {
                let r = req!(GetUserTheme);
                json(self.get_user_theme(&r).await?)?
            }
            "save_user_theme" => {
                let r = req!(SaveUserTheme);
                json(self.save_user_theme(&r).await?)?
            }
            "delete_user_theme" => {
                let r = req!(DeleteUserTheme);
                json(self.delete_user_theme(&r).await?)?
            }
            "get_peers" => {
                let _r = req!(GetPeers);
                json(self.get_peers().await?)?
            }
            "add_peer" => {
                let r = req!(AddPeer);
                json(self.add_peer(&r).await?)?
            }
            "remove_peer" => {
                let r = req!(RemovePeer);
                json(self.remove_peer(&r).await?)?
            }
            "set_discover_peers" => {
                let r = req!(SetDiscoverPeers);
                json(self.set_discover_peers(&r).await?)?
            }
            "set_target_peers" => {
                let r = req!(SetTargetPeers);
                json(self.set_target_peers(&r).await?)?
            }
            "set_network" => {
                let r = req!(SetNetwork);
                json(self.set_network(&r).await?)?
            }
            "set_network_override" => {
                let r = req!(SetNetworkOverride);
                json(self.set_network_override(&r).await?)?
            }
            "get_networks" => {
                let _r = req!(GetNetworks);
                json(self.get_networks())?
            }
            "get_network" => {
                let _r = req!(GetNetwork);
                json(self.get_network().await?)?
            }
            "set_delta_sync" => {
                let r = req!(SetDeltaSync);
                json(self.set_delta_sync(&r).await?)?
            }
            "set_delta_sync_override" => {
                let r = req!(SetDeltaSyncOverride);
                json(self.set_delta_sync_override(&r).await?)?
            }
            "set_change_address" => {
                let r = req!(SetChangeAddress);
                json(self.set_change_address(&r).await?)?
            }
            // The tipping subsystem (#378): tip.get_config / set_config / get_ledger / manual /
            // notify_consumed / dev_tick. Reachable only when the engine is attached
            // ([`Self::with_tipping`]); mutations are paired-token gated by the transport (§7.12).
            m if m.starts_with("tip.") => self.dispatch_tip(m, body).await?,
            other => {
                return Err(Error::not_found(format!(
                    "unknown or unsupported method: {other}"
                )));
            }
        };
        serde_json::to_string(&value).map_err(|e| Error::internal(format!("serialize: {e}")))
    }

    /// The first-class sync-status snapshot (#369): the tri-state ([`SyncLifecycle`]) derived from
    /// the wallet DB's synced peak + initial-catch-up flag, plus the synced peak height. The WS
    /// transport pushes this whenever it changes; the resolver/content transport is untouched.
    pub async fn sync_status(&self) -> Result<super::events::SyncStatus> {
        use super::events::{SyncLifecycle, SyncStatus};
        let st = self.db.sync_state().await?;
        Ok(SyncStatus {
            state: if st.initial_sync_complete {
                SyncLifecycle::Synced
            } else {
                SyncLifecycle::Syncing
            },
            peak_height: st.peak_height,
            // Until a chain tip is separately tracked, the best-known target is the synced peak.
            target_height: st.peak_height,
        })
    }

    /// Dispatch a `tip.*` method to the attached tipping engine (#378). A node without the engine
    /// attached reports the method unavailable. Reads (`get_config`/`get_ledger`) are open; the
    /// mutations (`set_config`/`manual`/`notify_consumed`/`dev_tick`) are paired-token gated by the
    /// transport (SPEC §7.12).
    async fn dispatch_tip(&self, method: &str, body: &str) -> Result<Value> {
        let engine = self
            .tipping
            .as_ref()
            .ok_or_else(|| Error::not_found("tipping is not enabled on this node"))?;
        let body_s = if body.trim().is_empty() { "{}" } else { body };
        #[derive(serde::Deserialize, Default)]
        struct StoreReq {
            #[serde(default)]
            store_id: String,
        }
        #[derive(serde::Deserialize, Default)]
        struct LedgerReq {
            #[serde(default)]
            since_ts: Option<u64>,
        }
        let parse = |label: &str| -> Result<StoreReq> {
            serde_json::from_str::<StoreReq>(body_s)
                .map_err(|e| Error::api(format!("invalid request for {label}: {e}")))
        };
        match method {
            "tip.get_config" => json(engine.get_config().await),
            "tip.set_config" => {
                let cfg: super::tipping::TippingConfig = serde_json::from_str(body_s)
                    .map_err(|e| Error::api(format!("invalid tip.set_config: {e}")))?;
                engine.set_config(cfg).await?;
                json(engine.get_config().await)
            }
            "tip.get_ledger" => {
                let r: LedgerReq = serde_json::from_str(body_s)
                    .map_err(|e| Error::api(format!("invalid tip.get_ledger: {e}")))?;
                json(engine.get_ledger(r.since_ts).await)
            }
            "tip.manual" => {
                let r = parse("tip.manual")?;
                if r.store_id.trim().is_empty() {
                    return Err(Error::api("tip.manual requires store_id"));
                }
                json(engine.manual_tip(&r.store_id).await?)
            }
            "tip.notify_consumed" => {
                let r = parse("tip.notify_consumed")?;
                if r.store_id.trim().is_empty() {
                    return Err(Error::api("tip.notify_consumed requires store_id"));
                }
                json(engine.auto_tip_for_store(&r.store_id).await?)
            }
            "tip.dev_tick" => json(engine.dev_daily_tip().await?),
            other => Err(Error::not_found(format!(
                "unknown or unsupported method: {other}"
            ))),
        }
    }
}

// ---- free helpers ---------------------------------------------------------

fn json<T: Serialize>(v: T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| Error::internal(format!("serialize: {e}")))
}

/// The key-touching signing methods (§18.9/§18.9a/§18.23) — the ones that obtain the signer and
/// produce a BLS signature. After any of these, [`WalletBackend::dispatch`] consumes the one-shot
/// per-transaction sign grant (§18.24), so the next signature requires a fresh `auth.sign_unlock`
/// (the "one sign-unlock authorizes exactly one signature" invariant). `tip.manual`/`tip.dev_tick`/
/// `tip.notify_consumed` are included because each builds+signs a $DIG tip through the SAME signer — a
/// grant must never leak past a tip into a later spend. (The record-update actions, network/theme
/// settings, and the tip reads/`tip.set_config` are NOT here — they do not sign.)
const SIGNING_METHODS: &[&str] = &[
    "send_xch",
    "bulk_send_xch",
    "send_cat",
    "bulk_send_cat",
    "combine",
    "split",
    "multi_send",
    "sign_coin_spends",
    "submit_transaction",
    "make_offer",
    "take_offer",
    "combine_offers",
    "cancel_offer",
    "create_did",
    "bulk_mint_nfts",
    "transfer_nfts",
    "transfer_dids",
    "mint_option",
    "transfer_options",
    "exercise_options",
    // Tipping (#377/#378) signs a $DIG spend through the SAME signer, so it too consumes the one-shot
    // grant — an armed grant must never survive an auto-tip into a later free signature (#432 Finding 6).
    "tip.manual",
    "tip.dev_tick",
    "tip.notify_consumed",
];

/// Whether `method` is a key-touching signing method (see [`SIGNING_METHODS`]).
fn is_signing_method(method: &str) -> bool {
    SIGNING_METHODS.contains(&method)
}

/// Parse a wire [`Amount`] to `u64` (rejecting values beyond `u64`).
fn amount_u64(a: &Amount) -> Result<u64> {
    a.to_u64()
        .ok_or_else(|| Error::api("amount exceeds u64 range".to_string()))
}

/// Parse a wire asset id (`None` = XCH) to a 32-byte hash.
fn opt_asset_id(id: &Option<String>) -> Result<Option<Bytes32>> {
    match id {
        None => Ok(None),
        Some(s) => Ok(Some(singleton::bytes32_from_hex(s)?)),
    }
}

/// The current unix time in seconds (0 if the clock is before the epoch).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse a stored status token into an [`OfferRecordStatus`] (unknown → `Active`).
fn parse_offer_status(s: &str) -> OfferRecordStatus {
    match s {
        "pending" => OfferRecordStatus::Pending,
        "completed" => OfferRecordStatus::Completed,
        "cancelled" => OfferRecordStatus::Cancelled,
        "expired" => OfferRecordStatus::Expired,
        _ => OfferRecordStatus::Active,
    }
}

/// Render a stored [`OfferDbRow`] as the Sage [`OfferRecord`] wire shape (`None` if the
/// stored summary JSON is corrupt).
fn offer_row_to_record(row: &OfferDbRow) -> Option<OfferRecord> {
    let summary: OfferSummary = serde_json::from_str(&row.summary_json).ok()?;
    Some(OfferRecord {
        offer_id: row.offer_id.clone(),
        offer: row.offer.clone(),
        status: parse_offer_status(&row.status),
        creation_timestamp: row.creation_timestamp as u64,
        summary,
    })
}

/// Normalize a Sage `nft_id`/`did_id` to the stored hex launcher id: a bech32m singleton
/// address decodes to its 32-byte launcher id; a hex id is used as-is (lowercased).
fn normalize_singleton_id(id: &str) -> String {
    if let Some(ph) = decode_address(id) {
        return ph;
    }
    id.strip_prefix("0x").unwrap_or(id).to_ascii_lowercase()
}

/// Greedily select CAT coin rows (largest first) covering `target`. Errors if they cannot.
///
/// The ordering and the refusal are [`super::selection::select_largest_first`]'s, shared with the
/// offer builder and with the mirror lifecycle's operator-scoped selector so that one money
/// algorithm has one implementation. What stays here is the part that is genuinely about this coin
/// SET: the DB stores an amount as a decimal string, and an unparseable one counts as zero — which
/// can only make a selection refuse, never over-fund.
fn select_cat_rows(rows: Vec<CoinRow>, target: u64) -> Result<Vec<CoinRow>> {
    super::selection::select_largest_first(rows, target, |r| {
        (r.amount.parse::<u64>().unwrap_or(0), r.coin_id.clone())
    })
    .map_err(|s| {
        Error::api(format!(
            "insufficient CAT balance: have {}, need {}",
            s.have, s.need
        ))
    })
}

/// Encode a puzzle-hash hex as a bech32m address with `prefix`.
fn encode_address(puzzle_hash_hex: &str, prefix: &str) -> Option<String> {
    let ph = puzzle_hash_hex
        .strip_prefix("0x")
        .unwrap_or(puzzle_hash_hex);
    let bytes: [u8; 32] = hex::decode(ph).ok()?.try_into().ok()?;
    chia_wallet_sdk::utils::Address::new(bytes.into(), prefix.to_string())
        .encode()
        .ok()
}

/// Normalize a puzzle-hash hex for identity scoping (#407): strip an optional `0x` prefix
/// and lowercase, so client-supplied hashes match the DB's `hex::encode` form.
pub(super) fn normalize_ph(ph: &str) -> String {
    ph.strip_prefix("0x").unwrap_or(ph).to_ascii_lowercase()
}

/// A hex identifier in the spelling the DB stores: bare, lowercase.
///
/// The `coins` table is written with `hex::encode`, so a lookup key must be reduced to that same
/// spelling or a coin the replica holds reads as a miss. `control.wallet.coinById` already
/// canonicalises its argument, but a direct Rust caller does not, and a normalisation applied only
/// at the wire edge is one the library cannot rely on.
fn normalize_hex_id(id: &str) -> String {
    normalize_ph(id)
}

/// Decode a bech32m address into its puzzle-hash hex (any valid prefix).
fn decode_address(address: &str) -> Option<String> {
    chia_wallet_sdk::utils::Address::decode(address)
        .ok()
        .map(|a| hex::encode(a.puzzle_hash))
}

/// Map a [`FallbackCoin`] (a chain read) into a [`CoinRow`] for the wallet DB. `asset_id`/`hint`
/// start `None` (a raw coin read does not reveal a CAT's TAIL — the lineage attribution pass fills
/// them in, mirroring the direct-peer sync's `coin_state_to_row`).
fn fallback_coin_to_row(c: &FallbackCoin) -> CoinRow {
    CoinRow {
        coin_id: c.coin_id.clone(),
        parent_coin_info: c.parent_coin_info.clone(),
        puzzle_hash: c.puzzle_hash.clone(),
        amount: c.amount.to_string(),
        created_height: c.created_height.map(i64::from),
        spent_height: c.spent_height.map(i64::from),
        asset_id: None,
        hint: None,
        created_timestamp: c.created_timestamp.map(|t| t as i64),
        spent_timestamp: c.spent_timestamp.map(|t| t as i64),
    }
}

/// A coin is spendable iff it is confirmed (`created_height` set) and unspent.
fn is_spendable(c: &CoinRecord) -> bool {
    c.created_height.is_some() && c.spent_height.is_none()
}

fn filter_matches(c: &CoinRecord, mode: CoinFilterMode) -> bool {
    match mode {
        CoinFilterMode::All => true,
        // Sage's default: coins available to spend.
        CoinFilterMode::Selectable | CoinFilterMode::Owned => is_spendable(c),
        CoinFilterMode::Spent => c.spent_height.is_some(),
        // Clawback coins are not tracked in this PR.
        CoinFilterMode::Clawback => c.clawback_timestamp.is_some(),
    }
}

fn sort_coins(coins: &mut [CoinRecord], mode: CoinSortMode, ascending: bool) {
    coins.sort_by(|a, b| {
        let ord = match mode {
            CoinSortMode::CoinId => a.coin_id.cmp(&b.coin_id),
            CoinSortMode::Amount => a
                .amount
                .to_u64()
                .unwrap_or(0)
                .cmp(&b.amount.to_u64().unwrap_or(0)),
            CoinSortMode::CreatedHeight => a.created_height.cmp(&b.created_height),
            CoinSortMode::SpentHeight => a.spent_height.cmp(&b.spent_height),
            CoinSortMode::ClawbackTimestamp => a.clawback_timestamp.cmp(&b.clawback_timestamp),
        };
        if ascending {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn paginate(coins: Vec<CoinRecord>, offset: u32, limit: u32) -> Vec<CoinRecord> {
    coins
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect()
}

#[cfg(test)]
mod tests {
    // These tests EXERCISE the frozen custody surface on purpose: a freeze must not break custody
    // for whoever currently depends on it (dig_ecosystem#1701).
    #![allow(deprecated)]
    use super::super::db::DerivationRow;
    use super::super::db::PendingTransactionRow;
    use super::super::db::WalletDb;
    use super::super::fallback::mock::MockFallback;
    use super::super::fallback::EmptyFallback;
    use super::super::fallback::FallbackCoin;
    use super::*;

    /// The open-read rate bound is calibrated for what ONE TOKEN NOW BUYS (dig_ecosystem#3035).
    ///
    /// Since #3032 a token no longer buys one HTTP call to an oracle: it buys a corroborated peer
    /// ROUND — up to a dozen dials, then one request to each held peer. The numbers below are
    /// pinned so a future edit to either is a deliberate change to a test that says what they mean,
    /// and the ratio is asserted rather than only the values, because the calibration is the claim
    /// that a token costs roughly an order of magnitude more work than it used to.
    #[test]
    fn the_open_read_rate_bound_is_calibrated_for_a_peer_round() {
        assert_eq!(DEFAULT_FALLBACK_BURST, 16.0);
        assert_eq!(DEFAULT_FALLBACK_REFILL_PER_SEC, 2.0);
        assert!(
            DEFAULT_FALLBACK_BURST
                <= f64::from(u32::try_from(super::super::quorum::QUORUM_SAMPLE).unwrap()) * 4.0,
            "a burst that dwarfs the quorum a token pays for is a nominal bound"
        );
    }

    /// The puzzle hash every `xch_coin` test coin sits at — the identity reads scope to.
    fn test_ph() -> String {
        "00".repeat(32)
    }

    /// Opening the node's OWN operating wallet must NOT give the general wallet surface a signer.
    ///
    /// `crate::operator_wallet::OperatorWallet` exists so the mirror-coin lifecycle (dig-node#377)
    /// can sign its own spends. It is deliberately a value the caller holds, never something
    /// installed here — because installing it would activate every OTHER node-custodied spend path
    /// at once, default-on auto-tipping included, as an invisible side effect of enabling
    /// collateralisation. That is a behaviour change to a money path nobody reviewed.
    ///
    /// The fixture is built so the two halves are distinguishable. Asserting only that a fresh
    /// backend has no signer proves nothing about `operator_wallet` — it is true of a backend
    /// nothing has touched. So the wallet is genuinely opened first (asserted non-degenerate), and
    /// the backend is then re-read; and the third assertion shows the backend CAN hold a signer, so
    /// the `None` above is a fact about what was installed rather than about what is possible.
    #[tokio::test]
    async fn opening_the_operator_wallet_installs_no_signer_on_the_general_surface() {
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let be = backend_with(vec![], true).await;
        assert!(
            be.current_signer().is_none(),
            "baseline: a backend with nothing installed cannot sign"
        );

        let operator =
            crate::operator_wallet::OperatorWallet::from_phrase(PHRASE, Bytes32::from([7u8; 32]))
                .expect("the operator wallet really does open");
        assert_ne!(
            operator.owner_puzzle_hash(),
            Bytes32::default(),
            "so the assertion below is about installation, not about a failed open"
        );

        assert!(
            be.current_signer().is_none(),
            "the operator wallet is held by its caller and installed on nothing"
        );

        let installed = backend_with(vec![], true).await.with_signer(Arc::new(
            crate::sage::spend::WalletSigner::new(vec![], Bytes32::from([7u8; 32])),
        ));
        assert!(
            installed.current_signer().is_some(),
            "a backend CAN hold a signer, so the `None` above is a measurement and not a tautology"
        );
    }

    // ---- #410: the tip refusal names the state it is actually in ---------------------------

    /// A scratch config dir unique to this process AND thread, so parallel tests never share a
    /// custody manifest.
    /// The directory is OWNED by the returned guard: `TempDir`'s `Drop` removes the tree,
    /// including on an unwind, so a failing assertion cannot leak it (dig-node#370).
    fn refusal_scratch_dir(tag: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("dig-wallet-tip-refusal-{tag}-"))
            .tempdir()
            .expect("a scratch dir")
    }

    /// Ask `be` for a tip and return the `NotExecutable` reason, asserting on the way that the
    /// broadcaster was never reached — the refusal must be definitively PRE-broadcast.
    async fn tip_refusal_reason(be: &WalletBackend) -> String {
        let bc = crate::sage::spend::MockBroadcaster::default();
        let outcome = be
            .build_and_broadcast_dig_tip(Bytes32::from([9u8; 32]), 1_000, 0, &bc, None)
            .await
            .expect("a signer-absence refusal is an Ok(NotExecutable), never an Err");
        assert!(
            bc.sent.lock().unwrap().is_empty(),
            "the refusal must happen before anything is broadcast"
        );
        match outcome {
            super::super::tipping::TipSpendOutcome::NotExecutable { reason } => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The three signer-absence reasons must be DISTINCT strings, or the split is decorative:
    /// collapsing them back to one shared sentence would leave every equality assertion below
    /// still passing.
    #[test]
    fn the_three_signer_absence_reasons_are_pairwise_distinct() {
        use super::super::tipping::refusal;
        let all = [
            refusal::NO_SIGNER_CONFIGURED,
            refusal::WALLET_ENROLLED_BUT_UNOPENABLE,
            refusal::NO_WALLET_ENROLLED,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "each signer-absence state needs its own sentence");
            }
        }
    }

    /// The defect this ticket exists for: a backend with no custody view refused with
    /// `"wallet is locked"`, which is false — nothing is locked, nothing was ever configured.
    ///
    /// The negative assertion is on the SUBSTRING `"lock"`, not on the whole sentence, because the
    /// harm was never the exact wording: any sentence containing `lock`/`unlock` sends the reader
    /// after a remedy that does not exist on this node (SPEC §18.24 removed node-managed unlock).
    #[tokio::test]
    async fn with_no_custody_the_tip_refusal_says_unconfigured_and_never_mentions_a_lock() {
        let be = backend_with(vec![], true).await;
        assert!(
            be.current_signer().is_none(),
            "the fixture must genuinely have no signer, or this asserts nothing"
        );

        let reason = tip_refusal_reason(&be).await;
        assert_eq!(reason, super::super::tipping::refusal::NO_SIGNER_CONFIGURED);
        assert!(
            !reason.to_ascii_lowercase().contains("lock"),
            "an unlocked wallet must never be told it is locked; got {reason:?}"
        );
    }

    /// A wallet IS enrolled and its seed cannot be opened. This is the one state the old sentence
    /// was nearly right about — and it still must not claim a lock the user can open, so it names
    /// the sealed seed instead.
    #[tokio::test]
    async fn an_enrolled_wallet_refuses_the_tip_as_an_unopenable_seed() {
        let dir = refusal_scratch_dir("enrolled");
        WalletCustody::enroll_for_tests(dir.path(), "tip-refusal-fixture", &[BlsPair::new(410).pk]);
        let custody = WalletCustody::open(dir.path().to_path_buf());
        assert!(
            custody.any_wallet(),
            "the fixture must really enrol a wallet, or it is the empty-custody case in disguise"
        );

        let be = backend_with(vec![], true).await.with_custody(custody);
        let reason = tip_refusal_reason(&be).await;
        assert_eq!(
            reason,
            super::super::tipping::refusal::WALLET_ENROLLED_BUT_UNOPENABLE
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Custody attached, nothing enrolled — a different situation from both of the above, and the
    /// only one of the three a user fixes by creating a wallet.
    #[tokio::test]
    async fn custody_holding_no_wallet_refuses_the_tip_as_nothing_enrolled() {
        let dir = refusal_scratch_dir("empty");
        std::fs::create_dir_all(&dir).expect("create the scratch dir");
        let custody = WalletCustody::open(dir.path().to_path_buf());
        assert!(
            !custody.any_wallet(),
            "the fixture must really be empty, or it is the enrolled case in disguise"
        );

        let be = backend_with(vec![], true).await.with_custody(custody);
        assert_eq!(
            tip_refusal_reason(&be).await,
            super::super::tipping::refusal::NO_WALLET_ENROLLED
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The control that keeps the three assertions above from being true of everything: a backend
    /// that CAN sign gets past the signer guard entirely, and refuses for a different reason.
    /// Without this, a `signer_absence_reason` wired in unconditionally would pass every test here.
    #[tokio::test]
    async fn a_backend_that_can_sign_never_refuses_for_signer_absence() {
        use super::super::tipping::refusal;
        let be = backend_with(vec![], true).await.with_signer(Arc::new(
            crate::sage::spend::WalletSigner::new(vec![], Bytes32::from([7u8; 32])),
        ));
        assert!(
            be.current_signer().is_some(),
            "the control needs a backend that really can sign"
        );

        let reason = tip_refusal_reason(&be).await;
        for absent in [
            refusal::NO_SIGNER_CONFIGURED,
            refusal::WALLET_ENROLLED_BUT_UNOPENABLE,
            refusal::NO_WALLET_ENROLLED,
        ] {
            assert_ne!(
                reason, absent,
                "a signing backend reached the signer-absence branch"
            );
        }
    }

    async fn backend_with(coins: Vec<CoinRow>, synced: bool) -> WalletBackend {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&coins).await.unwrap();
        db.force_initial_sync_complete_for_test(synced)
            .await
            .unwrap();
        let fb = Arc::new(MockFallback::default());
        // Scope reads (#407) to the test coins' puzzle hash so identity-scoped reads see
        // them — mirrors a client `login` declaring its public puzzle hash.
        let cfg = WalletConfig {
            puzzle_hashes: vec![test_ph()],
            ..Default::default()
        };
        WalletBackend::new(db, fb, cfg)
    }

    fn xch_coin(id: &str, amount: u64, created: Option<i64>, spent: Option<i64>) -> CoinRow {
        CoinRow {
            coin_id: id.into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: "00".repeat(32),
            amount: amount.to_string(),
            created_height: created,
            spent_height: spent,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    // ---- control.wallet.balance: balance_for_address (#1851) -------------------------------

    /// A wallet-owned puzzle hash used across the balance tests, distinct from `test_ph`
    /// so the two identity axes never coincide by accident.
    fn owned_ph() -> String {
        "11".repeat(32)
    }

    fn owned_address() -> String {
        encode_address(&owned_ph(), "xch").unwrap()
    }

    /// A puzzle-hash hex string as the bytes the CAT curry takes. Panics on a bad fixture, which
    /// is the right outcome for a test constant.
    fn ph_bytes(ph: &str) -> Bytes32 {
        parse_puzzle_hash(ph).unwrap()
    }

    /// A public key standing in for an account enrolled through `control.wallet.watch`.
    ///
    /// Deliberately NOT `owned_ph`'s key: the enrolled address and the derivation-backed address
    /// must never coincide, or the control test below could pass for the wrong reason.
    fn enrolled_key() -> chia_bls::PublicKey {
        let mut seed = [0u8; 64];
        seed[0] = 77;
        chia_bls::SecretKey::from_seed(&seed).public_key()
    }

    /// A registry holding exactly `key`, backed by a temp dir the caller must keep alive — the
    /// registry persists to a file, so a dropped dir would take the registration with it.
    fn registry_with_key(
        key: &chia_bls::PublicKey,
    ) -> (super::super::watchlist::WatchRegistry, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let registry = super::super::watchlist::WatchRegistry::new(dir.path());
        assert_eq!(
            registry.watch(&[*key]),
            1,
            "the fixture must actually register"
        );
        (registry, dir)
    }

    /// A DB with `owned_ph` registered as a real HD derivation (the `scoped_to_wallet` axis),
    /// its sync flag set, and an optional peak — the fixture for the DB-path reads.
    async fn db_with_owned_derivation(synced: bool, peak: Option<u32>) -> WalletDb {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_derivation(&DerivationRow {
            hardened: false,
            index: 0,
            public_key: "aa".repeat(48),
            puzzle_hash: owned_ph(),
            address: owned_address(),
        })
        .await
        .unwrap();
        if synced {
            // A sync that COVERED this address, not merely a flag saying one finished: the read
            // router asks about coverage, and a flag with no covered set is exactly the state that
            // answered a newly enrolled address a dated zero (dig_ecosystem#2871).
            db.record_coverage(&CoveredSet::from_hex([owned_ph()]))
                .await
                .unwrap();
        }
        db.force_initial_sync_complete_for_test(synced)
            .await
            .unwrap();
        if let Some(h) = peak {
            db.set_peak(h, &"cc".repeat(32)).await.unwrap();
        }
        db
    }

    /// The page size every coin-read test that is NOT about paging asks for.
    ///
    /// Large enough that those tests see the whole fixture, so the paging change cannot silently
    /// truncate what they assert about — and named rather than a bare literal, so a reader can tell
    /// "this test does not care about the page" from "this test chose 100 for a reason".
    const TEST_PAGE: u32 = 100;

    fn coin_at_ph(
        id: &str,
        ph: &str,
        amount: u64,
        created: Option<i64>,
        spent: Option<i64>,
    ) -> CoinRow {
        CoinRow {
            coin_id: id.into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: ph.into(),
            amount: amount.to_string(),
            created_height: created,
            spent_height: spent,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    fn fallback_coin(
        id: &str,
        ph: &str,
        amount: u64,
        created: Option<u32>,
        spent: Option<u32>,
    ) -> FallbackCoin {
        FallbackCoin {
            coin_id: id.into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: ph.into(),
            amount,
            created_height: created,
            spent_height: spent,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    /// Scoped + synced ⇒ the DB path: `balance` counts ONLY confirmed unspent coins (excludes
    /// the spent coin AND the not-yet-confirmed one), while `pending` reports the coin whose
    /// `created_height` is NULL. The three coins have distinct states so a placement that
    /// conflated them (e.g. summing all unspent into `balance`) would change the numbers.
    #[tokio::test]
    async fn scoped_synced_reads_db_separating_confirmed_pending_and_spent() {
        let db = db_with_owned_derivation(true, Some(500)).await;
        db.upsert_coins(&[
            coin_at_ph("confirmed", &owned_ph(), 100, Some(10), None),
            coin_at_ph("spent", &owned_ph(), 50, Some(10), Some(20)),
            coin_at_ph("pending", &owned_ph(), 7, None, None),
        ])
        .await
        .unwrap();
        // A live fallback is attached but MUST NOT be consulted on the DB path.
        let fb = Arc::new(MockFallback::with_coins(vec![fallback_coin(
            "ghost",
            &owned_ph(),
            9999,
            Some(1),
            None,
        )]));
        let be = WalletBackend::new(db, fb.clone(), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_level_at(500));

        let r = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(r.balance, 100, "confirmed unspent only");
        assert_eq!(r.pending, 7, "created_height NULL coin");
        assert!(r.synced);
        assert_eq!(r.peak_height, Some(500), "peak from the real chain view");
        assert_eq!(fb.call_count(), 0, "DB path never touches the fallback");
    }

    /// $DIG is scoped by the canonical CAT asset id (`digstore_chain::dig::DIG_ASSET_ID`): a
    /// CAT coin hinted to the address with that asset id is counted, while an XCH coin at the
    /// same address is NOT — proving the asset routing is asset-id-scoped, not address-scoped.
    #[tokio::test]
    async fn dig_balance_scopes_by_canonical_cat_asset_id() {
        let dig = hex::encode(digstore_chain::dig::DIG_ASSET_ID);
        let db = db_with_owned_derivation(true, None).await;
        db.upsert_coins(&[
            CoinRow {
                coin_id: "cat".into(),
                parent_coin_info: "pp".into(),
                puzzle_hash: "cat-inner".into(),
                amount: "250".into(),
                created_height: Some(10),
                spent_height: None,
                asset_id: Some(dig.clone()),
                hint: Some(owned_ph()),
                created_timestamp: None,
                spent_timestamp: None,
            },
            coin_at_ph("xch", &owned_ph(), 100, Some(10), None),
        ])
        .await
        .unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );

        let dig_bal = be
            .balance_for_address(&owned_address(), BalanceAsset::DIG)
            .await
            .unwrap();
        assert_eq!(
            dig_bal.balance, 250,
            "the $DIG CAT coin, by canonical asset id"
        );
        let xch_bal = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(xch_bal.balance, 100, "XCH at the address, not the CAT");
    }

    /// An arbitrary (non-wallet) address routes to the LIVE fallback and returns its figures.
    #[tokio::test]
    async fn arbitrary_address_uses_fallback_tier() {
        let arb_ph = "22".repeat(32);
        let arbitrary = encode_address(&arb_ph, "xch").unwrap();
        let fb = Arc::new(MockFallback::with_coins(vec![
            fallback_coin("c1", &arb_ph, 42, Some(10), None),
            fallback_coin("pend", &arb_ph, 5, None, None),
        ]));
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb,
            WalletConfig::default(),
        );

        let r = be
            .balance_for_address(&arbitrary, BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(r.balance, 42, "confirmed fallback coin");
        assert_eq!(r.pending, 5, "unconfirmed fallback coin");
        assert_eq!(r.source, Source::Fallback);
    }

    /// A chain fallback that answers a HINT read the way the real one does: with EVERY coin
    /// hinted to the address, whatever asset it belongs to.
    ///
    /// `get_coin_records_by_hints` has no asset parameter, so this is not a pessimistic double —
    /// it is the shape of the tier. [`super::super::fallback::mock::MockFallback`] answers hint
    /// reads with an empty list, which cannot express a multi-asset hint set at all and so cannot
    /// see dig_ecosystem#2879.
    struct EveryHintedCoin(Vec<FallbackCoin>);

    #[async_trait::async_trait]
    impl ChainFallback for EveryHintedCoin {
        fn is_live(&self) -> bool {
            true
        }
        async fn coin_records_by_puzzle_hashes(&self, phs: &[String]) -> Result<Vec<FallbackCoin>> {
            Ok(self
                .0
                .iter()
                .filter(|c| phs.contains(&c.puzzle_hash))
                .cloned()
                .collect())
        }
        async fn coin_records_by_hints(&self, _hints: &[String]) -> Result<Vec<FallbackCoin>> {
            Ok(self.0.clone())
        }
        async fn coin_record_by_id(&self, _coin_id: &str) -> Result<Option<FallbackCoin>> {
            Ok(None)
        }
        async fn coin_spend(&self, _coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
            Ok(None)
        }
        async fn coin_records_by_parent(&self, _parent: &str) -> Result<Vec<FallbackCoin>> {
            Ok(vec![])
        }
    }

    /// The hinted-coin set every asset-scoping test below reads, and the truth about it.
    ///
    /// Returns `(fallback, owner_address)`. Every coin in it is hinted to the owner, so an
    /// asset-blind read returns all of them:
    ///
    /// * a plain **XCH** coin at the owner's own p2 hash, `100_000_000` mojos — the reported case
    ///   (dig_ecosystem#2879). `0.0001 XCH` is 10^8 mojos, and 10^8 base units rendered at
    ///   `$DIG`'s 3 decimals is exactly `100000`, which is the figure the user was shown. It must
    ///   NOT count toward `$DIG`.
    /// * a genuine **`$DIG`** CAT coin, `12_345` base units — it MUST still count. The value
    ///   carries significant digits low down on purpose: a round fixture passes under several
    ///   scales, and this defect IS a scale confusion.
    /// * a **foreign CAT** coin, `7_000_000` — a second asset hinted to the same address, so a
    ///   filter applied at the wrong layer changes the answer instead of preserving it.
    /// * a genuine **pending** `$DIG` coin, `678` — the pending figure must be asset-scoped too,
    ///   not only the confirmed sum.
    ///
    /// So the truth is `balance == 12_345`, `pending == 678`, over exactly one coin each.
    /// Summing the whole hint set answers `107_012_345`; discarding it answers `0`. Both are
    /// wrong, and in opposite directions — an over-filtered read tells a real `$DIG` holder they
    /// hold nothing, which is the same money lie mirrored.
    fn hinted_multi_asset_fixture() -> (Arc<dyn ChainFallback>, String) {
        let owner = ph_bytes(&owned_ph());
        let dig_ph = hex::encode(digstore_chain::cat::cat_puzzle_hash(
            owner,
            digstore_chain::dig::DIG_ASSET_ID,
        ));
        let foreign_ph = hex::encode(digstore_chain::cat::cat_puzzle_hash(
            owner,
            Bytes32::from([0x33u8; 32]),
        ));
        let coins = vec![
            fallback_coin("hinted-xch", &owned_ph(), 100_000_000, Some(10), None),
            fallback_coin("real-dig", &dig_ph, 12_345, Some(10), None),
            fallback_coin("foreign-cat", &foreign_ph, 7_000_000, Some(10), None),
            fallback_coin("pending-dig", &dig_ph, 678, None, None),
        ];
        (
            Arc::new(EveryHintedCoin(coins)),
            encode_address(&owned_ph(), "xch").unwrap(),
        )
    }

    /// **dig_ecosystem#2879 — a hint is not an asset.** A `$DIG` balance served by the chain
    /// fallback counts ONLY `$DIG` coins.
    ///
    /// The fallback tier reads CAT coins by HINT, and a hint read is asset-blind by construction.
    /// The pre-fix code computed the CAT asset id, applied it in the DB branch, dropped it in the
    /// fallback branch, and summed every hinted coin as `$DIG` — reporting a holding the user does
    /// not have. See [`hinted_multi_asset_fixture`] for why each coin in the fixture is there.
    #[tokio::test]
    async fn a_fallback_dig_balance_counts_only_dig_coins() {
        let (fb, address) = hinted_multi_asset_fixture();
        let be = backend_over(fb).await;

        let r = be
            .balance_for_address(&address, BalanceAsset::DIG)
            .await
            .unwrap();
        assert_eq!(r.source, Source::Fallback, "the tier under test");
        assert_eq!(
            r.balance, 12_345,
            "only the genuine $DIG coin — not the hinted XCH coin, not the foreign CAT"
        );
        assert_eq!(r.pending, 678, "the pending figure is asset-scoped too");
    }

    /// The other direction of the same read: an XCH balance is unaffected by the hinted CATs.
    ///
    /// Kept separate rather than folded above, because it is the control that proves the filter
    /// did not simply suppress the fallback tier: the same fixture, the same address, a real
    /// non-zero answer.
    #[tokio::test]
    async fn a_fallback_xch_balance_counts_only_the_coin_at_the_address() {
        let (fb, address) = hinted_multi_asset_fixture();
        let be = backend_over(fb).await;

        let r = be
            .balance_for_address(&address, BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(
            r.balance, 100_000_000,
            "the coin AT the p2 hash; a CAT never sits there"
        );
    }

    /// **The same defect in the coin LIST (dig_ecosystem#2879).** `coins_for_address` is the
    /// balance read unreduced and shares its fallback branch verbatim, so it handed a caller
    /// building a `$DIG` spend a set of XCH and foreign-CAT coins.
    ///
    /// Asserting the coin IDS, not the count: a count would pass for an implementation that kept
    /// the wrong single coin.
    #[tokio::test]
    async fn a_fallback_dig_coin_list_contains_only_dig_coins() {
        let (fb, address) = hinted_multi_asset_fixture();
        let be = backend_over(fb).await;

        let r = be
            .coins_for_address(&address, BalanceAsset::DIG, None, TEST_PAGE)
            .await
            .unwrap();
        let mut ids: Vec<&str> = r.coins.iter().map(|c| c.coin_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            ["pending-dig", "real-dig"],
            "the $DIG coins only — a spend built on the others would be built on foreign inputs"
        );
    }

    /// A backend scoped to the fixture's owner address with an EMPTY, unsynced in-memory DB —
    /// so every wallet-data read routes to [`Source::Fallback`] (dig-node#306).
    async fn unsynced_backend_scoped_to_owner(fb: Arc<dyn ChainFallback>) -> WalletBackend {
        WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb,
            WalletConfig {
                puzzle_hashes: vec![owned_ph()],
                ..WalletConfig::default()
            },
        )
    }

    /// **dig-node#306 — a $DIG holder on an unsynced replica must not read as holding none.**
    ///
    /// The Sage-parity coin read `return`ed an empty vector for ANY CAT while unsynced, so this
    /// wallet's two real $DIG coins were reported as zero coins. That is not a smaller answer, it
    /// is a different claim: the caller is told the holding does not exist.
    ///
    /// Asserting the coin IDS rather than a count, and asserting the CONTENTS of the set rather
    /// than its non-emptiness, because the nearest wrong implementation is the unfiltered hint
    /// read — which is also non-empty, and which reports the foreign CAT and a hinted XCH coin as
    /// $DIG (dig_ecosystem#2879, the over-report this must not trade itself for).
    #[tokio::test]
    async fn an_unsynced_cat_coin_read_returns_the_holders_coins_not_an_empty_set() {
        let (fb, _address) = hinted_multi_asset_fixture();
        let be = unsynced_backend_scoped_to_owner(fb).await;

        let dig_hex = hex::encode(digstore_chain::dig::DIG_ASSET_ID);
        let r = be
            .get_coins(&GetCoins {
                asset_id: Some(dig_hex),
                offset: 0,
                limit: TEST_PAGE,
                sort_mode: CoinSortMode::default(),
                filter_mode: CoinFilterMode::default(),
                ascending: true,
            })
            .await
            .unwrap();

        let mut ids: Vec<&str> = r.coins.iter().map(|c| c.coin_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            ["real-dig"],
            concat!(
                "the confirmed $DIG coin: not an empty set (the #306 under-report), and not ",
                "the hinted XCH or foreign CAT (the #2879 over-report)"
            )
        );
        // `pending-dig` has no created height and the default filter mode excludes unconfirmed
        // coins — pinned here so a later widening of that filter is a deliberate change rather
        // than an accident that starts offering unconfirmed value to a caller.
        assert!(!ids.contains(&"pending-dig"));
    }

    /// The control that makes the test above load-bearing in the OTHER direction: asking for a
    /// DIFFERENT CAT on the same unsynced replica returns that CAT's coin — not $DIG's.
    ///
    /// Without this, an implementation that ignored `asset_id` entirely and returned every hinted
    /// coin would still have to be caught by the assertion above; with it, one that hard-codes
    /// $DIG's scoping (the obvious partial fix) fails here.
    #[tokio::test]
    async fn an_unsynced_read_for_a_different_cat_is_scoped_to_that_cat() {
        let (fb, _address) = hinted_multi_asset_fixture();
        let be = unsynced_backend_scoped_to_owner(fb).await;

        let r = be
            .get_coins(&GetCoins {
                asset_id: Some(hex::encode(foreign_asset_id())),
                offset: 0,
                limit: TEST_PAGE,
                sort_mode: CoinSortMode::default(),
                filter_mode: CoinFilterMode::default(),
                ascending: true,
            })
            .await
            .unwrap();

        let ids: Vec<&str> = r.coins.iter().map(|c| c.coin_id.as_str()).collect();
        assert_eq!(ids, ["foreign-cat"]);
    }

    /// **A spendable-coin COUNT is the same read reduced, and it lied the same way (#306).**
    ///
    /// `get_spendable_coin_count` shares `wallet_coins`, so it answered `0` for a wallet holding
    /// $DIG — and a zero count is what a spend builder consults before refusing. The XCH control
    /// in the same test proves the count was never simply suppressed for every asset.
    #[tokio::test]
    async fn an_unsynced_spendable_count_sees_the_holders_cat_coins() {
        let (fb, _address) = hinted_multi_asset_fixture();
        let be = unsynced_backend_scoped_to_owner(fb).await;

        let dig = be
            .get_spendable_coin_count(&GetSpendableCoinCount {
                asset_id: Some(hex::encode(digstore_chain::dig::DIG_ASSET_ID)),
            })
            .await
            .unwrap();
        assert_eq!(
            dig.count, 1,
            concat!(
                "the ONE confirmed $DIG coin — `pending-dig` has no created height and is ",
                "not spendable, so a count of 2 would mean unconfirmed value was offered ",
                "to a spend"
            )
        );

        let xch = be
            .get_spendable_coin_count(&GetSpendableCoinCount { asset_id: None })
            .await
            .unwrap();
        assert_eq!(xch.count, 1, "control: the XCH arm is unchanged");
    }

    /// An UNPARSEABLE `asset_id` fails the read rather than silently answering about XCH
    /// (dig-node#306).
    ///
    /// The tempting implementation of `from_asset_id_hex` treats a bad id as "no CAT", which
    /// hands a caller who asked about one token a confident, non-empty answer about a different
    /// one. That is worse than the empty set this ticket removed.
    #[tokio::test]
    async fn an_unparseable_asset_id_fails_rather_than_answering_about_xch() {
        let (fb, _address) = hinted_multi_asset_fixture();
        let be = unsynced_backend_scoped_to_owner(fb).await;

        let r = be
            .get_coins(&GetCoins {
                asset_id: Some("not-hex".to_string()),
                offset: 0,
                limit: TEST_PAGE,
                sort_mode: CoinSortMode::default(),
                filter_mode: CoinFilterMode::default(),
                ascending: true,
            })
            .await;
        assert!(r.is_err(), "a mistyped asset id must not resolve to XCH");
    }

    /// The asset id of the fixture's non-$DIG CAT — the "foreign-cat" coin's TAIL.
    ///
    /// Named rather than inlined because the point of the widening test below is that a caller can
    /// ask for THIS id, and the fixture and the request must be provably the same asset.
    fn foreign_asset_id() -> Bytes32 {
        Bytes32::from([0x33u8; 32])
    }

    /// **dig_ecosystem#3077 — a read for an ARBITRARY CAT returns that CAT's coins.**
    ///
    /// The load-bearing test of the widening. Before it, the asset type could name only XCH and
    /// $DIG, so this request was inexpressible; the nearest wrong implementation — one that
    /// widens the type but leaves the puzzle-hash filter derived from $DIG's id — answers this
    /// with an EMPTY list, which is indistinguishable from "you hold none of that CAT". No error,
    /// no warning, nothing red.
    ///
    /// A single-CAT fixture cannot see that defect, because $DIG's own read stays correct under
    /// it. So this asks for the SECOND CAT, on a fixture where $DIG is also present and hinted to
    /// the same address: a filter keyed on the wrong asset returns `[]` or returns `real-dig`, and
    /// both differ from the truth.
    #[tokio::test]
    async fn a_fallback_read_for_an_arbitrary_cat_returns_that_cats_coins() {
        let (fb, address) = hinted_multi_asset_fixture();
        let be = backend_over(fb).await;

        let r = be
            .coins_for_address(
                &address,
                BalanceAsset::Cat(foreign_asset_id()),
                None,
                TEST_PAGE,
            )
            .await
            .unwrap();
        let ids: Vec<&str> = r.coins.iter().map(|c| c.coin_id.as_str()).collect();
        assert_eq!(
            ids,
            ["foreign-cat"],
            "the requested CAT's coin, and ONLY it — not $DIG's, not the hinted XCH coin"
        );
        assert_eq!(r.source, Source::Fallback, "the tier under test");
    }

    /// The honesty half of the same widening: a read for a CAT the address genuinely holds none of
    /// answers an EMPTY list from a real chain consultation — it does not fail, and it does not
    /// borrow another asset's coins.
    ///
    /// Paired with the test above deliberately. That one alone passes for an implementation that
    /// filters nothing and happens to return one coin; this one alone passes for an implementation
    /// that returns `[]` for every CAT. Together they pin the filter to the requested id: the same
    /// fixture and the same address answer differently for two different asset ids.
    #[tokio::test]
    async fn a_fallback_read_for_an_unheld_cat_answers_an_honest_empty_list() {
        let (fb, address) = hinted_multi_asset_fixture();
        let be = backend_over(fb).await;

        let r = be
            .coins_for_address(
                &address,
                BalanceAsset::Cat(Bytes32::from([0x77u8; 32])),
                None,
                TEST_PAGE,
            )
            .await
            .unwrap();
        assert!(
            r.coins.is_empty(),
            "the address holds no coin of this CAT, got {:?}",
            r.coins.iter().map(|c| &c.coin_id).collect::<Vec<_>>()
        );
        assert_eq!(
            r.source,
            Source::Fallback,
            "an empty list is an ANSWER from a consulted chain, not a suppressed read"
        );
    }

    /// The wire form the widened asset travels as is the PUBLISHED one, in both directions.
    ///
    /// Round-tripping through `dig-node-control-interface`'s `Asset` rather than asserting
    /// strings: the node must not acquire a second spelling of the contract it serves. $DIG is
    /// checked explicitly because it is the one value whose two representations
    /// (`BalanceAsset::DIG` and `Cat(<the canonical id>)`) must be the SAME value — if they were
    /// not, a `"dig"` request and a `{"cat":"a406…"}` request would scope to different assets.
    #[test]
    fn the_asset_type_round_trips_through_the_published_wire_type() {
        for asset in [
            BalanceAsset::Xch,
            BalanceAsset::DIG,
            BalanceAsset::Cat(foreign_asset_id()),
        ] {
            let wire: ControlAsset = asset.into();
            assert_eq!(BalanceAsset::from(wire), asset, "round trip of {asset:?}");
        }
        assert_eq!(
            BalanceAsset::from(ControlAsset::DIG),
            BalanceAsset::DIG,
            "the published $DIG id and this module's must be the same asset"
        );
    }

    /// **The instrument (#2233).** A coinset-served answer reports the FALLBACK tier and
    /// reports NOTHING about the local replica — even when that replica is fully caught up.
    ///
    /// The fixture is chosen to distinguish the fix from the nearest wrong implementation:
    /// the DB here is `force_initial_sync_complete_for_test(true)` with peak `9_000_000`, while the
    /// queried address is unscoped, so routing still picks `Fallback`. The pre-fix code read
    /// `synced` / `peak_height` OUTSIDE the tier decision and would answer
    /// `synced: true, peak_height: Some(9_000_000)` on this input — a third-party oracle read
    /// presented as a synced local one. An unsynced-DB fixture (the shipped state today, and
    /// the one every prior test used) cannot see that difference at all: it is honest by
    /// coincidence, which is exactly how this defect survived.
    #[tokio::test]
    async fn a_fallback_served_read_never_reports_the_dbs_sync_state() {
        let arb_ph = "22".repeat(32);
        let arbitrary = encode_address(&arb_ph, "xch").unwrap();
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        db.set_peak(9_000_000, &"cc".repeat(32)).await.unwrap();
        let fb = Arc::new(MockFallback::with_coins(vec![fallback_coin(
            "c1",
            &arb_ph,
            42,
            Some(10),
            None,
        )]));
        let be = WalletBackend::new(db, fb, WalletConfig::default());

        let r = be
            .balance_for_address(&arbitrary, BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(r.balance, 42, "the coinset figure, so the tier really ran");
        assert_eq!(r.source, Source::Fallback, "the tier that answered");
        assert!(
            !r.synced,
            "a coinset answer is never a synced local read, however synced the DB is"
        );
        assert_eq!(
            r.peak_height, None,
            "the DB's peak does not bound a coinset answer's freshness"
        );
    }

    /// The DB tier reports itself as the DB tier, with the replica's real peak.
    ///
    /// **Reachability caveat (#2234):** this asserts the arm, not an end-to-end path. The
    /// `scoped_to_wallet` axis is `db.derivation_exists`, and `upsert_derivation` has no
    /// production caller — so on a shipped node the `derivations` table is empty, `scoped`
    /// is always `false`, and `balance_for_address` NEVER reaches this arm. The fixture
    /// writes the derivation directly. This is fixture-only coverage until #2234 replaces
    /// the routing axis with a production-written subscription watermark.
    #[tokio::test]
    async fn a_db_served_read_reports_the_db_tier_and_the_replicas_peak() {
        let db = db_with_owned_derivation(true, Some(500)).await;
        db.upsert_coins(&[coin_at_ph("confirmed", &owned_ph(), 100, Some(10), None)])
            .await
            .unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_chain_peer_tier_for_tests(peers_level_at(500));

        let r = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(r.source, Source::Db, "the tier that answered");
        assert!(r.synced);
        assert_eq!(r.peak_height, Some(500), "the replica's own peak");
    }

    /// An ENROLLED address reads from the replica, not from the third-party oracle.
    ///
    /// This is the production path `a_db_served_read_reports_the_db_tier_and_the_replicas_peak`
    /// could only reach through a hand-written fixture: `upsert_derivation` has no production
    /// caller, so on a shipped node the `derivations` table is empty and `scoped` was false
    /// forever. An externally enrolled key IS subscribed and its coins ARE synced into the
    /// replica, so the replica is authoritative for it (dig_ecosystem#2866, #2234).
    ///
    /// Measured before the fix on a real node: a fully synced replica following the user's own
    /// account still logged `wallet balance read routed to the third-party chain oracle` on every
    /// read.
    #[tokio::test]
    async fn an_enrolled_address_reads_from_the_replica_not_the_oracle() {
        let (registry, _dir) = registry_with_key(&enrolled_key());
        let ph = normalize_ph(&hex::encode(
            super::super::sync_supervisor::puzzle_hash_for(&enrolled_key()),
        ));

        // NO derivation row for this address: the registry is the ONLY reason it is in scope.
        let db = WalletDb::open_in_memory().await.unwrap();
        // A catch-up that actually COVERED this key -- the state a running node reaches, and the
        // only state in which the replica may answer for it (dig_ecosystem#2871).
        complete_catch_up_over(&db, &[enrolled_key()]).await;
        db.upsert_coins(&[coin_at_ph("enrolled", &ph, 700, Some(10), None)])
            .await
            .unwrap();

        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_watchlist(registry)
        .with_chain_peer_tier_for_tests(peers_level_at(500));

        let r = be
            .balance_for_address(&encode_address(&ph, "xch").unwrap(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(
            r.source,
            Source::Db,
            "an address the replica follows must be answered by the replica"
        );
        assert!(r.synced, "only a Db answer may report itself synced");
        assert_eq!(r.balance, 700, "the figure the replica holds");
    }

    // -----------------------------------------------------------------------
    // Enrolment widens the scope the catch-up covered (dig_ecosystem#2871)
    // -----------------------------------------------------------------------

    /// A second enrollable key, distinct from [`enrolled_key`] — the K2 of the ticket's sequence.
    fn second_enrolled_key() -> chia_bls::PublicKey {
        let mut seed = [0u8; 64];
        seed[0] = 91;
        chia_bls::SecretKey::from_seed(&seed).public_key()
    }

    fn address_of(key: &chia_bls::PublicKey) -> String {
        let ph = normalize_ph(&hex::encode(
            super::super::sync_supervisor::puzzle_hash_for(key),
        ));
        encode_address(&ph, "xch").unwrap()
    }

    /// Complete a catch-up over EXACTLY `covered`, the way a real session does: ONE write carrying
    /// the peak, the flag, and the set it ran over.
    ///
    /// There is deliberately no helper that latches the flag WITHOUT a covered set. That
    /// combination is the defect, and a fixture able to express it invites a test that pins the old
    /// behaviour back into place.
    async fn complete_catch_up_over(db: &WalletDb, covered: &[chia_bls::PublicKey]) {
        let phs: Vec<_> = covered
            .iter()
            .map(super::super::sync_supervisor::puzzle_hash_for)
            .collect();
        db.complete_catch_up(
            &super::super::db::CatchUpReplay::finished_at(None, 500, "cc".repeat(32), &phs)
                .unwrap(),
        )
        .await
        .unwrap();
    }

    /// **Proves (dig_ecosystem#2871):** a key enrolled AFTER the catch-up completed is not answered
    /// from a replica that never followed it.
    ///
    /// THE DEFECT THIS PINS. `initial_sync_complete` means "a catch-up finished over the set
    /// resolved at session start"; `watchlist_follows` asks "is this key registered right now".
    /// Nothing ordered the two, so the first read of a newly enrolled address found
    /// `db_synced = true` and `scoped = true`, queried the DB for a scope it had never followed,
    /// and answered `balance: 0, synced: true, source: "db"` for a funded wallet.
    /// `coins_for_address` answered `coins: []` the same way — and its own doc reads that as "a
    /// chain WAS consulted", so a spend refuses with a shortfall that is not real. No attacker and
    /// no configuration: enrolling a second profile is enough.
    ///
    /// FIXTURE DESIGN — THE ORDER IS THE TEST. K1 is enrolled and the catch-up is completed FIRST,
    /// exactly as a running node reaches this state; only then is K2 enrolled. A fixture that
    /// enrols both keys before completing the catch-up describes a node that never had the bug and
    /// passes against the broken implementation.
    #[tokio::test]
    async fn a_key_enrolled_after_the_catch_up_is_not_answered_from_the_replica() {
        let (registry, _dir) = registry_with_key(&enrolled_key());
        let db = WalletDb::open_in_memory().await.unwrap();
        // The state a node reaches legitimately: K1's catch-up finished, over K1.
        complete_catch_up_over(&db, &[enrolled_key()]).await;

        let be = WalletBackend::new(
            db.clone(),
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_watchlist(registry);

        // K2 arrives afterwards — a second profile, or any additional key.
        assert_eq!(
            be.watch_keys(&[second_enrolled_key()]),
            Some(1),
            "the fixture must actually enrol a NEW key"
        );

        let result = be
            .balance_for_address(&address_of(&second_enrolled_key()), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(
            result.source,
            Source::Fallback,
            "a replica whose catch-up never covered this address answered for it anyway; it holds \
             nothing, so that answer is `balance 0` for a funded wallet"
        );
        assert!(!result.synced);
    }

    /// **Proves (F1):** a catch-up that STARTED before an enrolment cannot vouch for the key that
    /// arrived while it was still running.
    ///
    /// NEAREST WRONG IMPLEMENTATION: any fix that keeps a bare flag and clears it at the enrolment
    /// boundary — INCLUDING "clear it again once the catch-up returns". The supervisor resolves the
    /// subscription set BEFORE the catch-up starts, and a first catch-up replays from genesis over
    /// many batches, so an enrolment lands squarely inside that window; the completion then writes
    /// `initial_sync_complete = 1` over a set that never contained K2, and nothing repairs it.
    ///
    /// FIXTURE DESIGN — THE ORDER IS THE WHOLE TEST, and it is the REVERSE of the test above: K2 is
    /// enrolled BEFORE the completion lands, so the completion is the LAST writer. A fixture that
    /// completes the catch-up first passes against that wrong implementation and proves nothing.
    #[tokio::test]
    async fn a_catch_up_in_flight_cannot_vouch_for_a_key_enrolled_while_it_ran() {
        let (registry, _dir) = registry_with_key(&enrolled_key());
        let db = WalletDb::open_in_memory().await.unwrap();
        let be = WalletBackend::new(
            db.clone(),
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_watchlist(registry);

        // A catch-up is already running over {K1} — its subscription set is fixed. K2 enrols
        // mid-flight...
        assert_eq!(be.watch_keys(&[second_enrolled_key()]), Some(1));
        // ...and only NOW does that catch-up finish, over the set it actually ran over.
        complete_catch_up_over(&db, &[enrolled_key()]).await;

        let result = be
            .balance_for_address(&address_of(&second_enrolled_key()), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(
            result.source,
            Source::Fallback,
            "a completion that landed after the enrolment declared the replica authoritative for a \
             key its own subscription never contained"
        );
        assert!(!result.synced);
    }

    /// **Proves (F2):** enrolment does not depend on a SECOND write landing.
    ///
    /// NEAREST WRONG IMPLEMENTATION: enrol, then invalidate — the shape this change removes.
    /// Registration persists first and `watch` is idempotent, so a failed or interrupted
    /// invalidation left the widened set latched permanently: the client's retry enrolled nothing,
    /// an `added > 0` guard was therefore false, and the invalidation never ran at all. A second
    /// `watch` call IS that retry.
    ///
    /// FIXTURE DESIGN — the second call is the one under test and it must add ZERO. A test that
    /// calls `watch` once cannot distinguish "invalidated on the first call" from "no invalidation
    /// is needed", which is precisely the distinction that failed in the field.
    #[tokio::test]
    async fn a_repeated_enrolment_that_adds_nothing_still_leaves_the_new_key_uncovered() {
        let (registry, _dir) = registry_with_key(&enrolled_key());
        let db = WalletDb::open_in_memory().await.unwrap();
        complete_catch_up_over(&db, &[enrolled_key()]).await;
        let be = WalletBackend::new(
            db.clone(),
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_watchlist(registry);

        assert_eq!(be.watch_keys(&[second_enrolled_key()]), Some(1));
        assert_eq!(
            be.watch_keys(&[second_enrolled_key()]),
            Some(0),
            "the retry must add nothing — that is the condition under test"
        );

        let result = be
            .balance_for_address(&address_of(&second_enrolled_key()), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(
            result.source,
            Source::Fallback,
            "the replica answered for a key it never covered because the retry reported \
             `added = 0` and was read as nothing having changed"
        );
    }

    /// **Proves:** a re-announcement leaves the replica AUTHORITATIVE.
    ///
    /// `control.wallet.watch` is idempotent and dig-app re-announces its whole account on every
    /// unlock. NEAREST WRONG IMPLEMENTATION: treating any `watch` call as a widening — which holds
    /// a perfectly healthy node in permanent fallback for as long as its client keeps saying hello,
    /// an outage invented by the fix rather than found by it.
    ///
    /// Asserted on the ROUTING rather than on a flag, because routing is what a user feels.
    #[tokio::test]
    async fn re_announcing_a_known_key_leaves_the_replica_authoritative() {
        let (registry, _dir) = registry_with_key(&enrolled_key());
        let db = WalletDb::open_in_memory().await.unwrap();
        complete_catch_up_over(&db, &[enrolled_key()]).await;

        let be = WalletBackend::new(
            db.clone(),
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_watchlist(registry);

        assert_eq!(
            be.watch_keys(&[enrolled_key()]),
            Some(0),
            "re-announcing a known key must enrol nothing"
        );
        let result = be
            .balance_for_address(&address_of(&enrolled_key()), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(
            result.source,
            Source::Db,
            "a re-announcement that widened nothing sent a healthy replica to the oracle"
        );
    }

    /// **Proves:** NARROWING the followed set keeps the replica authoritative.
    ///
    /// NEAREST WRONG IMPLEMENTATION: comparing a whole-set FINGERPRINT for equality. Under it
    /// `control.wallet.unwatch` — a correct operation that REMOVES an address — would stop matching
    /// the recording and force a full resync, sending every read to the oracle for its duration. A
    /// catch-up over the wider set genuinely covered everything that remains, so the question has
    /// to be containment.
    #[tokio::test]
    async fn deregistering_a_key_leaves_the_remaining_ones_covered() {
        let (registry, _dir) = registry_with_key(&enrolled_key());
        let db = WalletDb::open_in_memory().await.unwrap();
        let be = WalletBackend::new(
            db.clone(),
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_watchlist(registry.clone());

        assert_eq!(be.watch_keys(&[second_enrolled_key()]), Some(1));
        // The catch-up covers BOTH keys, which is the state an `unwatch` starts from.
        complete_catch_up_over(&db, &[enrolled_key(), second_enrolled_key()]).await;
        registry.unwatch(&[second_enrolled_key()]);

        let result = be
            .balance_for_address(&address_of(&enrolled_key()), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(
            result.source,
            Source::Db,
            "removing an address invalidated a catch-up that still covers every address left"
        );
    }

    /// **Proves (variant 1b):** the point-read refresh may not declare the replica authoritative
    /// for addresses it never fetched.
    ///
    /// `refresh_tracked_coins` reads coins for CUSTODY's puzzle hashes only, then latches the
    /// global `initial_sync_complete`. An externally enrolled address is not in that set, so its
    /// coins were never requested — and the flag would make the replica authoritative for it
    /// PERMANENTLY, since nothing later clears it.
    ///
    /// FIXTURE DESIGN — the enrolled key is deliberately NOT one of custody's, which is the whole
    /// condition. A fixture enrolling custody's own key is covered by definition and would pass
    /// against the unfixed code.
    #[tokio::test]
    async fn a_custody_only_refresh_does_not_vouch_for_enrolled_addresses() {
        let (registry, _dir) = registry_with_key(&enrolled_key());
        let pair = BlsPair::new(2);
        let signer = Arc::new(WalletSigner::new(vec![pair.sk], Bytes32::new([0u8; 32])));
        let custody_ph = hex::encode(signer.puzzle_hashes().iter().next().unwrap());
        let db = WalletDb::open_in_memory().await.unwrap();
        let be = WalletBackend::new(
            db.clone(),
            Arc::new(MockFallback::with_coins(vec![FallbackCoin {
                coin_id: "aa".repeat(32),
                parent_coin_info: "11".repeat(32),
                puzzle_hash: custody_ph.clone(),
                amount: 7_000,
                created_height: Some(5),
                spent_height: None,
                created_timestamp: Some(1),
                spent_timestamp: None,
            }])),
            WalletConfig {
                puzzle_hashes: vec![custody_ph],
                ..Default::default()
            },
        )
        .with_signer(signer)
        .with_watchlist(registry);

        assert_eq!(
            be.refresh_tracked_coins().await.unwrap(),
            1,
            "the fixture must actually sync custody's own coin"
        );
        assert!(
            !db.is_synced().await.unwrap(),
            "a refresh that fetched only custody's addresses declared the replica authoritative \
             for an enrolled address whose coins it never requested — permanently, since nothing \
             clears the flag"
        );

        // The CONTROL: the same refresh on a node with nothing externally enrolled still latches,
        // so the guard did not simply switch the point-read path off.
        let db = WalletDb::open_in_memory().await.unwrap();
        let pair = BlsPair::new(2);
        let signer = Arc::new(WalletSigner::new(vec![pair.sk], Bytes32::new([0u8; 32])));
        let custody_ph = hex::encode(signer.puzzle_hashes().iter().next().unwrap());
        let be = WalletBackend::new(
            db.clone(),
            Arc::new(MockFallback::with_coins(vec![FallbackCoin {
                coin_id: "bb".repeat(32),
                parent_coin_info: "11".repeat(32),
                puzzle_hash: custody_ph.clone(),
                amount: 7_000,
                created_height: Some(5),
                spent_height: None,
                created_timestamp: Some(1),
                spent_timestamp: None,
            }])),
            WalletConfig {
                puzzle_hashes: vec![custody_ph],
                ..Default::default()
            },
        )
        .with_signer(signer);
        assert_eq!(be.refresh_tracked_coins().await.unwrap(), 1);
        assert!(
            db.is_synced().await.unwrap(),
            "a node with nothing externally enrolled stopped latching its own refresh"
        );
    }

    /// The CONTROL, and the reason the predicate is membership rather than "a registry exists".
    ///
    /// Widening `scoped` to any address would route a puzzle hash this replica does not subscribe
    /// to at the local DB — which holds no coins for it — and report a FUNDED wallet as EMPTY.
    /// That is the falsehood `initial_sync`'s `NoPuzzleHashes` refusal exists to prevent, arriving
    /// through a different door. A registry that follows one address must not vouch for another.
    #[tokio::test]
    async fn an_unfollowed_address_still_falls_back_even_with_a_registry_present() {
        let (registry, _dir) = registry_with_key(&enrolled_key());

        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        db.set_peak(500, &"cc".repeat(32)).await.unwrap();

        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_watchlist(registry);

        // `owned_ph` is a DIFFERENT address, in neither the derivations table nor the registry.
        let r = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(
            r.source,
            Source::Fallback,
            "an address the replica does not follow has no coins in the replica"
        );
        assert!(!r.synced, "a fallback answer is never a synced local view");
    }

    /// A synced, wallet-owned, EMPTY address is a SUCCESS with a zero figure — never an error.
    ///
    /// The replica is given a REAL peak, level with its peers. Its subject is the zero-versus-error
    /// distinction, but it also asserts `synced`, and it used to do so over a replica with NO peak
    /// of its own — pinning the precise pairing (`synced: true` beside an unknown height) that
    /// [`WalletBackend::replica_answer_is_current`] now refuses. A fixture holding a value its own
    /// rule forbids reads as a passing control while making the defect unfixable, so the fixture is
    /// what changed here, not the assertion: an honestly caught-up replica knows its own height,
    /// and this stays the suite's positive control against hardcoding `synced: false`.
    #[tokio::test]
    async fn synced_empty_address_is_zero_success_not_error() {
        let db = db_with_owned_derivation(true, Some(500)).await;
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_chain_peer_tier_for_tests(peers_level_at(500));
        let r = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(r.balance, 0);
        assert_eq!(r.pending, 0);
        assert!(r.synced);
    }

    /// The four failure shapes are DISTINCT, so each maps to its own wire error (never a `0`):
    /// invalid address, no chain source (arbitrary addr + no live fallback), not synced (own
    /// addr + no live fallback), and a read failure (live fallback that errors).
    #[tokio::test]
    async fn failure_shapes_are_distinct() {
        // Invalid address — does not decode as bech32m.
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            Arc::new(EmptyFallback),
            WalletConfig::default(),
        );
        assert_eq!(
            be.balance_for_address("not-an-address", BalanceAsset::Xch)
                .await,
            Err(BalanceError::InvalidAddress)
        );

        // No chain source: arbitrary address, DB synced, EmptyFallback (not live).
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default());
        let arbitrary = encode_address(&"33".repeat(32), "xch").unwrap();
        assert_eq!(
            be.balance_for_address(&arbitrary, BalanceAsset::Xch).await,
            Err(BalanceError::NoChainSource)
        );

        // Not synced: the wallet's OWN address, DB not synced, EmptyFallback (not live).
        let db = db_with_owned_derivation(false, None).await;
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default());
        assert_eq!(
            be.balance_for_address(&owned_address(), BalanceAsset::Xch)
                .await,
            Err(BalanceError::NotSynced)
        );

        // Read failed: arbitrary address routes to a LIVE fallback that errors.
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(db, Arc::new(ErringFallback), WalletConfig::default());
        assert!(matches!(
            be.balance_for_address(&arbitrary, BalanceAsset::Xch).await,
            Err(BalanceError::ReadFailed(_))
        ));
    }

    /// A live fallback whose reads always error — for the READ_FAILED shape.
    struct ErringFallback;
    #[async_trait::async_trait]
    impl ChainFallback for ErringFallback {
        async fn coin_records_by_puzzle_hashes(&self, _: &[String]) -> Result<Vec<FallbackCoin>> {
            Err(Error::internal("boom"))
        }
        async fn coin_records_by_hints(&self, _: &[String]) -> Result<Vec<FallbackCoin>> {
            Err(Error::internal("boom"))
        }
        async fn coin_record_by_id(&self, _: &str) -> Result<Option<FallbackCoin>> {
            Err(Error::internal("boom"))
        }
        async fn coin_spend(&self, _: &str) -> Result<Option<FallbackCoinSpend>> {
            Err(Error::internal("boom"))
        }
        async fn coin_records_by_parent(&self, _: &str) -> Result<Vec<FallbackCoin>> {
            Err(Error::internal("boom"))
        }
        // A live source whose reads fail — proves the READ_FAILED shape (#1851: the trait
        // default is now fail-closed, so a live double must say so explicitly).
        fn is_live(&self) -> bool {
            true
        }
    }

    // ---- control.wallet.coinById: coin_by_id (dig_ecosystem#2392) --------------------

    /// **A SPENT coin is returned, with its real spent height.**
    ///
    /// The address-scoped reads drop spent coins (`.filter(|c| c.spent_height.is_none())`) because
    /// a balance is about what you still hold. Inheriting that filter here would make the by-id
    /// read structurally unable to say "this coin is gone" — so a mint poll could never report
    /// failure, only await forever. The fixture holds BOTH a spent and an unspent coin so a
    /// filter would change the answer rather than merely fail to appear.
    #[tokio::test]
    async fn a_spent_coin_is_returned_with_its_spent_height() {
        let fb = Arc::new(MockFallback::with_coins(vec![
            fallback_coin("spent-one", &owned_ph(), 100, Some(10), Some(42)),
            fallback_coin("unspent-one", &owned_ph(), 100, Some(10), None),
        ]));
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb,
            WalletConfig::default(),
        );

        let spent = be.coin_by_id("spent-one").await.unwrap().coin.unwrap();
        assert_eq!(
            spent.spent_height,
            Some(42),
            "a spent coin is returned, carrying the height it went at"
        );
        let unspent = be.coin_by_id("unspent-one").await.unwrap().coin.unwrap();
        assert_eq!(
            unspent.spent_height, None,
            "and an unspent coin still reports no spend"
        );
    }

    /// A backend whose replica is authoritative at [`REPLICA_PEAK`], holds `held` and nothing else,
    /// and whose chain tier holds `on_chain` — so every test below varies ONE actor against the
    /// same truthful control.
    ///
    /// The two tiers deliberately report DIFFERENT amounts for the same coin id. That is what makes
    /// "which tier answered" observable in the returned value rather than only in a flag, so a fix
    /// that set the flags without moving the read fails here.
    async fn by_id_backend(
        held: &[CoinRow],
        on_chain: Vec<FallbackCoin>,
        peers: super::super::fallback::ChainPeerTier,
    ) -> (WalletBackend, Arc<MockFallback>) {
        let db = db_with_owned_derivation(true, Some(REPLICA_PEAK)).await;
        db.upsert_coins(held).await.unwrap();
        let fb = Arc::new(MockFallback::with_coins(on_chain));
        let be = WalletBackend::new(db, fb.clone(), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers);
        (be, fb)
    }

    /// The replica's figure for the shared fixture coin, and the chain tier's. Unequal by
    /// construction: an answer of `REPLICA_AMOUNT` could only have come from the replica.
    const REPLICA_AMOUNT: u64 = 100;
    const ORACLE_AMOUNT: u64 = 7;

    /// **Proves:** a coin the replica HOLDS, on a replica that is authoritative and level with its
    /// peers, is answered from the replica and SAYS SO — `source: db`, `synced: true`, and the
    /// replica's real peak (dig_ecosystem#2938).
    ///
    /// THE DEFECT THIS PINS. All three fields were unconditional literals — `Fallback`, `false`,
    /// `None` — emitted after an oracle read that ran whatever the node already knew. A consumer
    /// guarding on that warrant could never obtain one, so the guard degenerated into an
    /// unconditional refusal and ended every mint watch in "the chain could not be reached".
    ///
    /// FIXTURE DESIGN — the flags alone would not catch it. The two tiers report different amounts
    /// for the same id, so this asserts the read actually MOVED, not merely that its labels
    /// changed; and `call_count` pins that no oracle egress happened for a purely local answer.
    #[tokio::test]
    async fn a_coin_the_replica_holds_is_answered_from_the_replica_and_says_so() {
        let (be, fb) = by_id_backend(
            &[coin_at_ph(
                "watched",
                &owned_ph(),
                REPLICA_AMOUNT,
                Some(10),
                None,
            )],
            vec![fallback_coin(
                "watched",
                &owned_ph(),
                ORACLE_AMOUNT,
                Some(11),
                None,
            )],
            peers_level_at(REPLICA_PEAK),
        )
        .await;

        let r = be.coin_by_id("watched").await.unwrap();

        assert_eq!(
            r.coin.unwrap().amount,
            REPLICA_AMOUNT,
            "the replica's own figure, not the oracle's"
        );
        assert_eq!(r.source, Source::Db, "the tier that answered");
        assert!(
            r.synced,
            "the node held the coin and reported knowing nothing"
        );
        assert_eq!(
            r.peak_height,
            Some(REPLICA_PEAK),
            "the height this answer is as of"
        );
        assert_eq!(
            fb.call_count(),
            0,
            "a local answer disclosed the coin id to the oracle"
        );
    }

    /// **Proves:** a coin the replica does NOT hold still falls through to the chain tier, and is
    /// never reported as an authoritative absence.
    ///
    /// The control that keeps the test above from being satisfied by "if authoritative, answer from
    /// the DB". The replica here is authoritative and holds a DIFFERENT coin, so the wrong
    /// implementation returns `coin: None, source: db, synced: true` — proven absence for a coin
    /// this node merely does not watch, which would declare a live mint dead. Varying one actor
    /// (which coin is asked for) keeps the rest of the fixture truthful.
    #[tokio::test]
    async fn a_coin_the_replica_does_not_hold_still_falls_through_to_the_chain() {
        let (be, fb) = by_id_backend(
            &[coin_at_ph(
                "watched",
                &owned_ph(),
                REPLICA_AMOUNT,
                Some(10),
                None,
            )],
            vec![fallback_coin(
                "unwatched",
                &owned_ph(),
                ORACLE_AMOUNT,
                Some(11),
                None,
            )],
            peers_level_at(REPLICA_PEAK),
        )
        .await;

        let r = be.coin_by_id("unwatched").await.unwrap();

        assert_eq!(
            r.coin.expect("a replica miss is not an absence").amount,
            ORACLE_AMOUNT,
            "the chain tier's figure"
        );
        assert_eq!(fb.call_count(), 1, "the chain tier really ran");
        assert_eq!(r.source, Source::Fallback);
        assert!(!r.synced, "no local replica produced this answer");
        assert_eq!(
            r.peak_height, None,
            "a caller bounding confirmations reads control.wallet.peak"
        );
    }

    /// **Proves:** holding the coin is not enough — a replica that is NOT authoritative for the set
    /// it follows falls through to the chain tier for a coin it holds.
    ///
    /// The second control, and the one that keeps the eligibility test from being dropped as
    /// redundant. The fixture varies ONE thing from the passing case: a key is enrolled that the
    /// completed catch-up never covered, so the followed set outgrows the covered one (the #2871
    /// widening), while the coin, the peak and the peer tier are unchanged. An implementation that
    /// keys only on "is the coin in the DB" answers `REPLICA_AMOUNT` here — serving money from a
    /// replica that was never asked to follow it.
    #[tokio::test]
    async fn a_coin_held_by_a_non_authoritative_replica_is_not_served_from_it() {
        let (registry, _dir) = registry_with_key(&enrolled_key());
        let db = db_with_owned_derivation(true, Some(REPLICA_PEAK)).await;
        db.upsert_coins(&[coin_at_ph(
            "watched",
            &owned_ph(),
            REPLICA_AMOUNT,
            Some(10),
            None,
        )])
        .await
        .unwrap();
        let fb = Arc::new(MockFallback::with_coins(vec![fallback_coin(
            "watched",
            &owned_ph(),
            ORACLE_AMOUNT,
            Some(11),
            None,
        )]));
        let widened = WalletBackend::new(db, fb, WalletConfig::default())
            .with_watchlist(registry)
            .with_chain_peer_tier_for_tests(peers_level_at(REPLICA_PEAK));

        let r = widened.coin_by_id("watched").await.unwrap();

        assert_eq!(
            r.coin.unwrap().amount,
            ORACLE_AMOUNT,
            "a replica that does not cover what it follows served money anyway"
        );
        assert_eq!(r.source, Source::Fallback);
        assert!(!r.synced);
    }

    /// **Proves:** the replica-served answer's `synced` is MEASURED, not a literal — a replica that
    /// fell behind its peers serves the coin it holds, with its real peak, labelled stale.
    ///
    /// Without this, the passing case above is satisfied by `synced: true` hardcoded in the new
    /// arm, which is the #2869 defect reintroduced one read over. Varying only the peer tier keeps
    /// every other actor honest, and asserting the coin AND the peak pins "stale but still served"
    /// rather than "withheld".
    #[tokio::test]
    async fn a_behind_replica_serves_the_coin_it_holds_and_says_it_is_not_current() {
        let (be, _fb) = by_id_backend(
            &[coin_at_ph(
                "watched",
                &owned_ph(),
                REPLICA_AMOUNT,
                Some(10),
                None,
            )],
            vec![],
            peers_ahead_of_the_replica(),
        )
        .await;

        let r = be.coin_by_id("watched").await.unwrap();

        assert_eq!(r.source, Source::Db, "the replica stopped serving");
        assert_eq!(
            r.coin.unwrap().amount,
            REPLICA_AMOUNT,
            "the figure was withheld"
        );
        assert_eq!(
            r.peak_height,
            Some(REPLICA_PEAK),
            "a stale answer must still say WHAT it is as of"
        );
        assert!(
            !r.synced,
            "a replica {PEERS_AHEAD_BY} blocks behind reported its answer as current"
        );
    }

    /// A coin a chain source reports it does not have is a SUCCESSFUL `coin: None`, never an error —
    /// paired with the error shapes below so neither direction can be satisfied by collapsing
    /// the other.
    #[tokio::test]
    async fn an_unknown_coin_is_a_successful_none() {
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );
        assert_eq!(be.coin_by_id("nope").await.unwrap().coin, None);
    }

    /// The three ways of NOT reaching a chain are distinct errors, and NONE of them is `None`.
    #[tokio::test]
    async fn every_way_of_not_reaching_a_chain_is_a_distinct_error() {
        let db = || WalletDb::open_in_memory();

        let no_source = WalletBackend::new(
            db().await.unwrap(),
            Arc::new(EmptyFallback),
            WalletConfig::default(),
        );
        assert_eq!(
            no_source.coin_by_id("c1").await,
            Err(BalanceError::NoChainSource)
        );

        let erring = WalletBackend::new(
            db().await.unwrap(),
            Arc::new(ErringFallback),
            WalletConfig::default(),
        );
        assert!(matches!(
            erring.coin_by_id("c1").await,
            Err(BalanceError::ReadFailed(_))
        ));

        let limited = WalletBackend::new(
            db().await.unwrap(),
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_fallback_rate_limit(0.0, 0.0);
        assert_eq!(
            limited.coin_by_id("c1").await,
            Err(BalanceError::RateLimited)
        );
    }

    // ---- control.wallet.coinSpend + coinsByParent (dig_ecosystem#2572) ----------------

    /// A [`FallbackCoinSpend`] for `coin_id`. The programs are placeholders: this layer composes
    /// and pages, and the reveal VERIFICATION lives one tier down where a real CLVM fixture proves
    /// it (`fallback::chain_failure_tests`).
    fn fallback_spend(coin_id: &str) -> FallbackCoinSpend {
        FallbackCoinSpend {
            coin_id: coin_id.into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: "ph".into(),
            amount: 100,
            puzzle_reveal: "01".into(),
            solution: "80".into(),
        }
    }

    /// A child coin of `parent`, named so its id ordering is explicit in each test.
    fn child_of(parent: &str, coin_id: &str) -> FallbackCoin {
        FallbackCoin {
            coin_id: coin_id.into(),
            parent_coin_info: parent.into(),
            puzzle_hash: "ph".into(),
            amount: 1,
            created_height: Some(10),
            spent_height: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    async fn backend_over(fb: Arc<dyn ChainFallback>) -> WalletBackend {
        WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb,
            WalletConfig::default(),
        )
    }

    /// **A spend is composed with its coin record, so the answer carries a real `spent_height`.**
    ///
    /// The chain tier's spend read returns no heights at all, so a mapper that used only it would
    /// have to emit `spent_height: null` — and the contract requires a spend's coin to report the
    /// height it was spent at, because "when did this happen" is half of what a lineage walker is
    /// asking. **Catches** the single-read implementation, which is the obvious one.
    #[tokio::test]
    async fn a_spend_is_composed_with_its_record_so_it_carries_a_spent_height() {
        let fb = Arc::new(
            MockFallback::with_coins(vec![fallback_coin(
                "spent-one",
                &owned_ph(),
                100,
                Some(10),
                Some(42),
            )])
            .with_spends(vec![fallback_spend("spent-one")]),
        );
        let be = backend_over(fb).await;

        let spend = be
            .coin_spend("spent-one")
            .await
            .expect("a live source answers")
            .spend
            .expect("the chain knows this spend");

        assert_eq!(spend.coin.coin_id, "spent-one");
        assert_eq!(
            spend.coin.spent_height,
            Some(42),
            "a spend's coin must carry the height it was spent at"
        );
        assert_eq!(spend.puzzle_reveal, "01");
        assert_eq!(spend.solution, "80");
    }

    /// **An UNSPENT coin answers `spend: None` — a verdict, not an error.**
    ///
    /// The fixture holds the coin RECORD and no spend for it, which is exactly the state a mint
    /// poll observes before its funding coin is consumed. **Catches** an implementation that
    /// treated a missing spend as a failure: a caller polling for confirmation would then see an
    /// error on every poll before the spend lands, and could not tell that from a real outage.
    #[tokio::test]
    async fn an_unspent_coin_answers_with_no_spend_rather_than_an_error() {
        let fb = Arc::new(MockFallback::with_coins(vec![fallback_coin(
            "unspent-one",
            &owned_ph(),
            100,
            Some(10),
            None,
        )]));
        let be = backend_over(fb).await;

        let result = be.coin_spend("unspent-one").await.expect("an answer");

        assert_eq!(result.spend, None);
        assert_eq!(result.source, Source::Fallback);
        assert!(!result.synced);
        assert_eq!(result.peak_height, None);
    }

    /// **A spend whose coin no record knows is a CONTRADICTION, and fails closed.**
    ///
    /// A source that reports a spend of a coin it has no record of is disagreeing with itself. The
    /// tempting recovery is to emit the spend with `spent_height: null` — but a caller cannot tell
    /// an absent height from an unconfirmed one, so it would read a fabricated answer as a real
    /// observation. **Catches** exactly that recovery. The fixture holds the spend and NO coin.
    #[tokio::test]
    async fn a_spend_with_no_coin_record_is_refused_rather_than_reported_without_a_height() {
        let fb = Arc::new(MockFallback::default().with_spends(vec![fallback_spend("ghost")]));
        let be = backend_over(fb).await;

        assert!(
            matches!(
                be.coin_spend("ghost").await,
                Err(BalanceError::ReadFailed(_))
            ),
            "a spend with no coin record must fail closed"
        );
    }

    /// **A spend whose record calls the coin UNSPENT is the same contradiction, and also fails.**
    ///
    /// Its own test because it takes a different branch from the one above — the record EXISTS
    /// here — so an implementation that only checked for a missing record would pass that test and
    /// emit a "spend" of a coin nothing on chain says was spent. That is the shape a caller reads
    /// as "the mint landed".
    #[tokio::test]
    async fn a_spend_whose_record_calls_the_coin_unspent_is_refused() {
        let fb = Arc::new(
            MockFallback::with_coins(vec![fallback_coin("odd", &owned_ph(), 100, Some(10), None)])
                .with_spends(vec![fallback_spend("odd")]),
        );
        let be = backend_over(fb).await;

        assert!(
            matches!(be.coin_spend("odd").await, Err(BalanceError::ReadFailed(_))),
            "a spend of a coin the record calls unspent must fail closed"
        );
    }

    /// **Every way of not reaching a chain is a distinct error, and none of them is `spend: None`.**
    ///
    /// The three-valued rule at the layer that serves it. `spend: None` tells a caller the coin is
    /// still unspent — which is the go-ahead to spend it — so an outage wearing that shape invites
    /// a double-spend. All three refusals are asserted together because collapsing any one of them
    /// into another loses the remedy the caller needs (upgrade / retry / back off).
    #[tokio::test]
    async fn no_chain_source_rate_limit_and_read_failure_are_never_an_absent_spend() {
        let no_source = backend_over(Arc::new(EmptyFallback)).await;
        assert_eq!(
            no_source.coin_spend("c1").await,
            Err(BalanceError::NoChainSource)
        );

        let erring = backend_over(Arc::new(ErringFallback)).await;
        assert!(matches!(
            erring.coin_spend("c1").await,
            Err(BalanceError::ReadFailed(_))
        ));

        let limited = backend_over(Arc::new(MockFallback::default()))
            .await
            .with_fallback_rate_limit(0.0, 0.0);
        assert_eq!(
            limited.coin_spend("c1").await,
            Err(BalanceError::RateLimited)
        );

        // The paired direction, on the SAME shape of double: a live source that genuinely has no
        // spend DOES answer None. Without this the three assertions above are satisfied by a
        // method that errors unconditionally.
        let live = backend_over(Arc::new(MockFallback::with_coins(vec![]))).await;
        assert_eq!(live.coin_spend("c1").await.expect("an answer").spend, None);
    }

    /// **The same three refusals for the children read, and none of them is an empty page.**
    ///
    /// An empty child list means *that spend created nothing*, which ends a lineage walk. The
    /// live-but-childless control at the end is what stops an unconditionally-erroring
    /// implementation from passing.
    #[tokio::test]
    async fn no_chain_source_rate_limit_and_read_failure_are_never_an_empty_child_page() {
        let no_source = backend_over(Arc::new(EmptyFallback)).await;
        assert_eq!(
            no_source.coins_by_parent("p", None, 100).await,
            Err(BalanceError::NoChainSource)
        );

        let erring = backend_over(Arc::new(ErringFallback)).await;
        assert!(matches!(
            erring.coins_by_parent("p", None, 100).await,
            Err(BalanceError::ReadFailed(_))
        ));

        let limited = backend_over(Arc::new(MockFallback::default()))
            .await
            .with_fallback_rate_limit(0.0, 0.0);
        assert_eq!(
            limited.coins_by_parent("p", None, 100).await,
            Err(BalanceError::RateLimited)
        );

        let live = backend_over(Arc::new(MockFallback::with_coins(vec![]))).await;
        let page = live
            .coins_by_parent("p", None, 100)
            .await
            .expect("an answer");
        assert!(page.coins.is_empty());
        assert!(page.complete, "a childless parent is a COMPLETE answer");
        assert_eq!(
            page.cursor, None,
            "an empty page has nothing to resume from"
        );
    }

    /// **`complete` is derived from what REMAINS, not from whether the page filled.**
    ///
    /// The single most likely defect in this method, and the reason this test is shaped the way it
    /// is. The naive `complete = coins.len() < limit` agrees with the correct derivation on almost
    /// every input; the two differ EXACTLY when the child count is an integer multiple of the page
    /// size. So the fixture is 4 children at a limit of 2 — an exact multiple — and the first page
    /// is full and NOT the whole set.
    ///
    /// A fixture of, say, 5 children at a limit of 2 would pass under BOTH derivations and prove
    /// nothing. Under the naive one, a lineage walker reading page 1 of an exactly-divisible child
    /// set concludes the branch ends there and silently presents a partial lineage as whole.
    ///
    /// The second page is asserted too: it is where the naive derivation would report `false` on a
    /// genuinely final full page, stalling the walk in the other direction.
    #[tokio::test]
    async fn complete_distinguishes_a_full_page_from_the_whole_child_set() {
        let fb = Arc::new(MockFallback::with_coins(vec![
            child_of("p", "aa"),
            child_of("p", "bb"),
            child_of("p", "cc"),
            child_of("p", "dd"),
        ]));
        let be = backend_over(fb).await;

        let first = be.coins_by_parent("p", None, 2).await.expect("page 1");
        assert_eq!(ids(&first.coins), vec!["aa", "bb"]);
        assert!(
            !first.complete,
            "a page that filled exactly is NOT evidence the child set ended"
        );
        assert_eq!(first.cursor.as_deref(), Some("bb"));

        let second = be
            .coins_by_parent("p", Some("bb"), 2)
            .await
            .expect("page 2");
        assert_eq!(ids(&second.coins), vec!["cc", "dd"]);
        assert!(
            second.complete,
            "the final page is complete even though it is FULL — 4 children over pages of 2 \
             leaves nothing after 'dd'"
        );
        assert_eq!(second.cursor.as_deref(), Some("dd"));
    }

    /// **A truncated page ALWAYS carries a cursor: `{complete: false, cursor: null}` is
    /// unrepresentable.**
    ///
    /// The contract specifies the two fields independently, so that contradiction is expressible on
    /// the wire and is forbidden nowhere in the type. A client receiving it either re-requests the
    /// identical page forever or silently restarts the walk from the beginning — an infinite stall
    /// or a silent re-scan. The server is where it has to be impossible.
    ///
    /// Asserted across EVERY page of a real multi-page walk rather than on one hand-picked page, so
    /// it cannot pass by happening to sample a page where the invariant holds. The converse pairing
    /// — `complete: true` WITH a cursor — is legitimate (a whole non-empty final page still has a
    /// last child) and is deliberately not forbidden here.
    #[tokio::test]
    async fn a_truncated_page_never_arrives_without_a_cursor_to_resume_from() {
        let fb = Arc::new(MockFallback::with_coins(
            (0..7).map(|i| child_of("p", &format!("c{i}"))).collect(),
        ));
        let be = backend_over(fb).await;

        let mut after: Option<String> = None;
        let mut pages = 0;
        loop {
            let page = be
                .coins_by_parent("p", after.as_deref(), 2)
                .await
                .expect("a page");
            pages += 1;
            if !page.complete {
                assert!(
                    page.cursor.is_some(),
                    "page {pages} says more children remain and gives nothing to resume from: \
                     {page:?}"
                );
            }
            match (page.complete, page.cursor) {
                (true, _) => break,
                (false, Some(cursor)) => after = Some(cursor),
                (false, None) => unreachable!("asserted above"),
            }
            assert!(pages < 10, "the walk must terminate");
        }
        assert_eq!(pages, 4, "7 children over pages of 2 is four pages");
    }

    /// **Children come back in ASCENDING `coin_id` order, whatever order the source used.**
    ///
    /// The cursor names a position in an order, so without a total, stable one a walk repeats some
    /// children and skips others. **Catches** an implementation that forwards the source's order:
    /// the fixture is supplied in DESCENDING order, so passing through unchanged fails, and the
    /// tier underneath merges peer and coinset answers and promises no order at all.
    ///
    /// The paging assertion is what makes the ordering load-bearing rather than cosmetic — a
    /// resume that used the source's order would skip `bb` entirely here.
    #[tokio::test]
    async fn children_are_ordered_by_coin_id_regardless_of_the_sources_order() {
        let fb = Arc::new(MockFallback::with_coins(vec![
            child_of("p", "dd"),
            child_of("p", "bb"),
            child_of("p", "cc"),
            child_of("p", "aa"),
        ]));
        let be = backend_over(fb).await;

        let all = be.coins_by_parent("p", None, 100).await.expect("one page");
        assert_eq!(ids(&all.coins), vec!["aa", "bb", "cc", "dd"]);

        let resumed = be
            .coins_by_parent("p", Some("aa"), 100)
            .await
            .expect("resumed");
        assert_eq!(
            ids(&resumed.coins),
            vec!["bb", "cc", "dd"],
            "resume is STRICTLY after the cursor in ascending id order"
        );
    }

    /// **`after_coin_id` is STRICTLY after: the cursor child is never handed out twice.**
    ///
    /// An inclusive boundary (`>=`) repeats one child on every page of a walk, which a caller
    /// summing amounts or counting outputs double-counts. The single-child fixture makes the
    /// off-by-one unmissable: inclusive returns one row, strict returns none.
    #[tokio::test]
    async fn resuming_from_a_cursor_never_repeats_that_child() {
        let fb = Arc::new(MockFallback::with_coins(vec![child_of("p", "only")]));
        let be = backend_over(fb).await;

        let page = be
            .coins_by_parent("p", Some("only"), 100)
            .await
            .expect("a page");

        assert!(page.coins.is_empty(), "got {:?}", ids(&page.coins));
        assert!(page.complete);
        assert_eq!(page.cursor, None);
    }

    /// **Only the named parent's children are returned.**
    ///
    /// The read is one hop over a caller-supplied id; another parent's child grafted into the page
    /// becomes a forged branch of the caller's lineage. The fixture holds children of two parents
    /// so a pass-through of everything the source held would fail.
    #[tokio::test]
    async fn another_parents_children_are_not_in_the_page() {
        let fb = Arc::new(MockFallback::with_coins(vec![
            child_of("p", "mine"),
            child_of("other", "theirs"),
        ]));
        let be = backend_over(fb).await;

        let page = be.coins_by_parent("p", None, 100).await.expect("a page");
        assert_eq!(ids(&page.coins), vec!["mine"]);
    }

    /// The coin ids of a page, for order assertions.
    fn ids(coins: &[WalletCoin]) -> Vec<&str> {
        coins.iter().map(|c| c.coin_id.as_str()).collect()
    }

    // ---- the chain transport dig-app needs (dig_ecosystem#2376) ----------------------

    /// A [`SignedBundlePusher`] double: records what it was handed and answers as told.
    ///
    /// It can express ALL THREE outcomes — accepted, mempool-refused, unreachable — because a
    /// double that could only accept could not tell a refusal from an outage, which is the exact
    /// distinction these tests exist to pin.
    struct FakePusher {
        answer: std::sync::Mutex<Option<std::result::Result<PushOutcome, String>>>,
        pushed: std::sync::Mutex<Vec<chia_protocol::SpendBundle>>,
    }

    impl FakePusher {
        fn answering(answer: std::result::Result<PushOutcome, String>) -> Arc<Self> {
            Arc::new(Self {
                answer: std::sync::Mutex::new(Some(answer)),
                pushed: std::sync::Mutex::new(Vec::new()),
            })
        }
        fn accepting() -> Arc<Self> {
            Self::answering(Ok(PushOutcome {
                accepted: true,
                transaction_id: Some("tx".repeat(32)),
                rejection: None,
                verdict: "SUCCESS".into(),
            }))
        }
    }

    #[async_trait::async_trait]
    impl super::super::chain::SignedBundlePusher for FakePusher {
        async fn push(&self, bundle: &chia_protocol::SpendBundle) -> Result<PushOutcome> {
            self.pushed.lock().unwrap().push(bundle.clone());
            match self.answer.lock().unwrap().clone() {
                Some(Ok(outcome)) => Ok(outcome),
                Some(Err(e)) => Err(Error::internal(e)),
                None => Err(Error::internal("no answer configured")),
            }
        }
    }

    /// A real, signed-shaped bundle in the hex form the wire carries.
    fn a_signed_bundle_hex() -> String {
        use chia_protocol::{Bytes32, Coin, CoinSpend, Program, SpendBundle};
        let coin = Coin::new(Bytes32::new([7u8; 32]), Bytes32::new([8u8; 32]), 42);
        let spend = CoinSpend::new(coin, Program::from(vec![0x01]), Program::from(vec![0x80]));
        super::super::chain::encode_signed_bundle(&SpendBundle::new(
            vec![spend],
            Default::default(),
        ))
        .unwrap()
    }

    /// **The DB path returns REAL coins, not a sum.** Three coins in three states, so an
    /// implementation that returned all rows (or dropped the unconfirmed one) fails here: the spent
    /// coin must be gone, the unconfirmed one must be PRESENT and marked unconfirmed.
    ///
    /// The live fallback holds a decoy coin that must never appear — the same control the balance
    /// test uses to prove the DB path did not secretly consult the oracle.
    #[tokio::test]
    async fn a_synced_owned_address_reads_its_real_unspent_coins_from_the_replica() {
        let db = db_with_owned_derivation(true, Some(500)).await;
        db.upsert_coins(&[
            coin_at_ph("confirmed", &owned_ph(), 100, Some(10), None),
            coin_at_ph("spent", &owned_ph(), 50, Some(10), Some(20)),
            coin_at_ph("pending", &owned_ph(), 7, None, None),
        ])
        .await
        .unwrap();
        let fb = Arc::new(MockFallback::with_coins(vec![fallback_coin(
            "ghost",
            &owned_ph(),
            9999,
            Some(1),
            None,
        )]));
        let be = WalletBackend::new(db, fb.clone(), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_level_at(500));

        let r = be
            .coins_for_address(&owned_address(), BalanceAsset::Xch, None, TEST_PAGE)
            .await
            .unwrap();

        let ids: Vec<&str> = r.coins.iter().map(|c| c.coin_id.as_str()).collect();
        assert_eq!(ids, vec!["confirmed", "pending"], "unspent coins only");
        assert_eq!(r.coins[0].amount, 100);
        assert_eq!(r.coins[0].created_height, Some(10));
        assert_eq!(
            r.coins[1].created_height, None,
            "a mempool-only coin is REPORTED, marked unconfirmed -- hiding it would under-report \
             what the address holds"
        );
        assert_eq!(r.source, Source::Db);
        assert!(r.synced);
        assert_eq!(r.peak_height, Some(500));
        assert_eq!(fb.call_count(), 0, "the DB path never touches the oracle");
    }

    /// The fallback path returns the oracle's coins, marked as NOT the replica's.
    #[tokio::test]
    async fn an_arbitrary_address_reads_its_coins_from_the_chain_tier() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let fb = Arc::new(MockFallback::with_coins(vec![
            fallback_coin("live", &"33".repeat(32), 1_750, Some(9), None),
            fallback_coin("already-spent", &"33".repeat(32), 5, Some(9), Some(11)),
        ]));
        let be = WalletBackend::new(db, fb, WalletConfig::default());
        let arbitrary = encode_address(&"33".repeat(32), "xch").unwrap();

        let r = be
            .coins_for_address(&arbitrary, BalanceAsset::Xch, None, TEST_PAGE)
            .await
            .unwrap();

        assert_eq!(
            r.coins
                .iter()
                .map(|c| c.coin_id.as_str())
                .collect::<Vec<_>>(),
            vec!["live"]
        );
        assert_eq!(r.coins[0].amount, 1_750);
        assert_eq!(r.source, Source::Fallback);
        assert!(!r.synced, "the replica did not produce this answer");
        assert_eq!(r.peak_height, None, "nor does it bound its freshness");
    }

    /// **The read that MUST NOT become an empty list.** Every way of failing to reach a chain is a
    /// distinct error; none of them is `coins: []`.
    ///
    /// Each case varies ONE thing from a working read — whether the tier is live, whether the
    /// replica is synced, whether the address is the wallet's — so a handler that collapsed them
    /// into one code, or into a success, fails on the case it collapsed.
    #[tokio::test]
    async fn a_chain_it_could_not_reach_is_an_error_never_an_empty_coin_list() {
        // No chain source: an arbitrary address, synced replica, a tier that is not live.
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default());
        let arbitrary = encode_address(&"33".repeat(32), "xch").unwrap();
        assert_eq!(
            be.coins_for_address(&arbitrary, BalanceAsset::Xch, None, TEST_PAGE)
                .await,
            Err(BalanceError::NoChainSource)
        );

        // Still syncing: the wallet's OWN address, replica not synced, tier not live.
        let db = db_with_owned_derivation(false, None).await;
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default());
        assert_eq!(
            be.coins_for_address(&owned_address(), BalanceAsset::Xch, None, TEST_PAGE)
                .await,
            Err(BalanceError::NotSynced)
        );

        // A live tier that errors: the answer is unknown, not empty.
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(db, Arc::new(ErringFallback), WalletConfig::default());
        assert!(matches!(
            be.coins_for_address(&arbitrary, BalanceAsset::Xch, None, TEST_PAGE)
                .await,
            Err(BalanceError::ReadFailed(_))
        ));

        // A malformed address never reaches the chain at all.
        let db = WalletDb::open_in_memory().await.unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default());
        assert_eq!(
            be.coins_for_address("not-an-address", BalanceAsset::Xch, None, TEST_PAGE)
                .await,
            Err(BalanceError::InvalidAddress)
        );
    }

    // -----------------------------------------------------------------------
    // `synced` describes THIS answer's freshness (dig_ecosystem#2869)
    // -----------------------------------------------------------------------

    /// The replica's peak in these fixtures, and a peer tier far enough ahead to be unambiguous.
    ///
    /// The gap is drawn FROM the production bound rather than invented: `FOLLOWING_TOLERANCE` is
    /// four blocks, and a fixture sitting just inside it would assert the tolerance instead of the
    /// behaviour. 530 is the distance measured on the live node this ticket came from.
    const REPLICA_PEAK: u32 = 9_140_640;
    const PEERS_AHEAD_BY: u32 = 530;

    /// A tier whose peers announced a peak `PEERS_AHEAD_BY` blocks past the replica's.
    /// An OBSERVABLE peer tier level with a replica at `peak`.
    ///
    /// Tests whose subject is routing or coin content still read `synced`, and
    /// [`WalletBackend::replica_answer_is_current`] refuses to claim currency with no peer height
    /// to compare against. Without this the fixture would answer `synced: false` for a reason
    /// unrelated to what those tests exist to pin.
    fn peers_level_at(peak: u32) -> super::super::fallback::ChainPeerTier {
        super::super::fallback::ChainPeerTier {
            peer_count: Some(5),
            peak_height: Some(peak),
        }
    }

    fn peers_ahead_of_the_replica() -> super::super::fallback::ChainPeerTier {
        super::super::fallback::ChainPeerTier {
            peer_count: Some(5),
            peak_height: Some(REPLICA_PEAK + PEERS_AHEAD_BY),
        }
    }

    /// **Proves:** a replica that completed a catch-up and then fell BEHIND reports its figure as
    /// stale — `synced: false` — while still disclosing the height that figure is as of.
    ///
    /// THE DEFECT THIS PINS. `synced` was the literal `true` in the `Source::Db` arm, so it said
    /// "current" about every replica-served answer for as long as the process lived. It is not a
    /// small overstatement: `db_synced` is `initial_sync_complete`, which latches once and is
    /// cleared only by a backwards chain move, so a replica 530 blocks behind still routes here and
    /// still claimed to be at the tip.
    ///
    /// FIXTURE DESIGN — the answer must stay SERVED. A wrong fix suppresses the whole reading, or
    /// blanks the peak, and a test asserting only `!synced` would pass against it. Asserting the
    /// balance AND the peak alongside is what pins "stale but honest and still useful" rather than
    /// "withheld".
    #[tokio::test]
    async fn a_behind_replica_serves_its_figure_and_says_it_is_not_current() {
        let db = db_with_owned_derivation(true, Some(REPLICA_PEAK)).await;
        db.upsert_coin(&coin_at_ph(
            "aa",
            &owned_ph(),
            1_599_179_999_973,
            Some(1),
            None,
        ))
        .await
        .unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_ahead_of_the_replica());

        let result = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(result.source, Source::Db, "the replica stopped serving");
        assert_eq!(result.balance, 1_599_179_999_973, "the figure was withheld");
        assert_eq!(
            result.peak_height,
            Some(REPLICA_PEAK),
            "a stale answer must still say WHAT it is as of"
        );
        assert!(
            !result.synced,
            "a replica {PEERS_AHEAD_BY} blocks behind reported its figure as current"
        );
    }

    /// **Proves:** the honesty fix did not make every replica answer stale — a replica level with
    /// its peers still reports `synced: true`.
    ///
    /// The control. Without it, the test above is satisfied by `synced: false` hardcoded in place
    /// of `synced: true`, which trades one literal for another and would make an upgraded client
    /// distrust every reading the node ever gives it.
    #[tokio::test]
    async fn a_replica_level_with_its_peers_still_reports_synced() {
        let db = db_with_owned_derivation(true, Some(REPLICA_PEAK)).await;
        db.upsert_coin(&coin_at_ph("aa", &owned_ph(), 42, Some(1), None))
            .await
            .unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(super::super::fallback::ChainPeerTier {
                peer_count: Some(5),
                peak_height: Some(REPLICA_PEAK),
            });

        let result = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert!(result.synced, "a replica at the tip was reported as stale");
        assert_eq!(result.peak_height, Some(REPLICA_PEAK));
    }

    /// **Proves:** `chain_peak` cannot report `synced: true` about a replica that
    /// `control.wallet.syncStatus` is simultaneously calling `syncing` (dig-node#293).
    ///
    /// THE DEFECT THIS PINS. dig_ecosystem#2869 replaced the latched `initial_sync_complete` with
    /// a MEASURED freshness predicate at the balance and coin reads, and `chain_peak` was left
    /// behind on `db.is_synced()`. Measured on a running node: `sync-status` said `syncing` while
    /// `peak` said `synced: true`, in the same process at the same moment, on a replica 1,875
    /// blocks behind. `peak` is the endpoint a client uses to bound a confirmation, so the
    /// falsehood lands on exactly the read that decides whether money has settled.
    ///
    /// FIXTURE DESIGN. The replica must satisfy `initial_sync_complete` AND lag past
    /// `FOLLOWING_TOLERANCE`, because the latch is what the defect trusts: a fresh replica fails
    /// the latch and a caught-up one is genuinely current, so neither can exhibit the defect. The
    /// gap is `PEERS_AHEAD_BY` (530), drawn from the live measurement rather than invented, and far
    /// past the four-block tolerance.
    ///
    /// It asserts AGREEMENT with the balance read rather than just `!synced`: the two endpoints
    /// disagreeing is the reported bug, and a fix applied to one site while the other keeps its own
    /// predicate would satisfy a lone `!synced` assertion and re-open the same class of defect.
    #[tokio::test]
    async fn the_peak_is_not_reported_current_while_the_balance_read_calls_the_same_replica_stale()
    {
        let db = db_with_owned_derivation(true, Some(REPLICA_PEAK)).await;
        assert!(
            db.is_synced().await.unwrap(),
            "the fixture must satisfy the latch the defect trusted; otherwise it proves nothing"
        );
        db.upsert_coin(&coin_at_ph("aa", &owned_ph(), 42, Some(1), None))
            .await
            .unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_ahead_of_the_replica());

        let peak = be.chain_peak().await.unwrap();
        let balance = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();

        assert_eq!(
            peak.peak_height,
            Some(REPLICA_PEAK),
            "a stale peak must still say WHAT height it is, or a client loses its only bound"
        );
        assert!(
            !peak.synced,
            "`peak` called a replica {PEERS_AHEAD_BY} blocks behind current"
        );
        assert_eq!(
            peak.synced, balance.synced,
            "`peak` and the balance read disagreed about the freshness of one replica at one moment"
        );
    }

    /// **The control for the test above:** a replica level with its peers still reports
    /// `synced: true` from `chain_peak`.
    ///
    /// Without it, `synced: false` hardcoded in place of `synced: true` satisfies the test above —
    /// trading one literal for another, and telling every client that no reading this node ever
    /// gives is current.
    #[tokio::test]
    async fn a_replica_level_with_its_peers_still_reports_a_synced_peak() {
        let db = db_with_owned_derivation(true, Some(REPLICA_PEAK)).await;
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_level_at(REPLICA_PEAK));

        assert_eq!(
            be.chain_peak().await.unwrap(),
            ChainPeak {
                peak_height: Some(REPLICA_PEAK),
                synced: true,
            },
            "a replica at the tip was reported as stale"
        );
    }

    /// **Proves:** an UNOBSERVABLE peer tier is not a licence to claim currency — a node with no
    /// chain peer that has announced a height serves its figure labelled stale.
    ///
    /// This is the state a freshly-started node sits in, and the one a node with no reachable chain
    /// peer sits in indefinitely. [`super::sync_supervisor::is_following`] answers `true` there by
    /// design (an absent second opinion is not an accusation on a status endpoint), so a money read
    /// delegating to it unnarrowed pairs `synced: true` with an arbitrarily old `peak_height` — the
    /// stale-presented-as-current claim this PR exists to remove.
    ///
    /// FIXTURE DESIGN — `peak_height: None` is what makes the tier unobservable, and it is the only
    /// axis varied from [`a_replica_level_with_its_peers_still_reports_synced`], which stays green
    /// as the honest control. The replica is deliberately CAUGHT UP (`initial_sync_complete`, a
    /// present peak, a real coin), so nothing but the missing peer height can explain a `false`;
    /// asserting the balance and the peak alongside pins "stale but served" over "withheld".
    #[tokio::test]
    async fn an_unobservable_peer_tier_is_never_reported_as_current() {
        let db = db_with_owned_derivation(true, Some(REPLICA_PEAK)).await;
        db.upsert_coin(&coin_at_ph(
            "aa",
            &owned_ph(),
            1_599_179_999_973,
            Some(1),
            None,
        ))
        .await
        .unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(super::super::fallback::ChainPeerTier {
                peer_count: None,
                peak_height: None,
            });

        let result = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(result.source, Source::Db, "the replica stopped serving");
        assert_eq!(result.balance, 1_599_179_999_973, "the figure was withheld");
        assert_eq!(
            result.peak_height,
            Some(REPLICA_PEAK),
            "a stale answer must still say WHAT it is as of"
        );
        assert!(
            !result.synced,
            "a figure no peer height could corroborate was reported as current"
        );
    }
    /// **Proves:** an UNKNOWN REPLICA height is never reported as current either — the other
    /// `None` arm of the same predicate, on the endpoint where it actually reaches production.
    ///
    /// [`super::sync_supervisor::is_following`] answers `true` when EITHER side is `None`, and
    /// [`WalletBackend::replica_answer_is_current`] narrowed only the peer side. `chain_peak`
    /// escapes the remaining arm by construction — it calls the gate inside `if let Some(peak)`,
    /// so it can never hand it a `None` replica. The balance and coin reads do not: they read
    /// `sync_state().peak_height` as an `Option` and pass it straight through. So the money reads,
    /// and only the money reads, still paired `synced: true` with `peak_height: null`.
    ///
    /// The state is production-reachable rather than hypothetical: `refresh_tracked_coins` latches
    /// the replica authoritative (`record_coverage` + `force_initial_sync_complete_for_test(true)`) WITHOUT
    /// ever writing a peak, which is exactly what `db_with_owned_derivation(true, None)` builds.
    ///
    /// FIXTURE DESIGN. The peer tier is deliberately HONEST and OBSERVABLE — level with the
    /// replica's neighbours, the same tier the passing control uses — so the missing REPLICA peak
    /// is the only axis varied and is the only thing that can explain a verdict. A hostile or
    /// unobservable tier would answer `false` for its own reasons and could not see this arm at
    /// all. Asserting AGREEMENT with `chain_peak` rather than a bare `!synced` is what makes the
    /// test load-bearing: the two endpoints disagreeing in one process at one moment is the
    /// reported defect, and `chain_peak` here takes its honest fallback arm (`synced: false`,
    /// height unknown), so a fix that hardcoded either literal on one side alone would show up as
    /// a disagreement rather than pass.
    #[tokio::test]
    async fn an_unknown_replica_height_is_never_reported_as_current() {
        let db = db_with_owned_derivation(true, None).await;
        assert!(
            db.is_synced().await.unwrap(),
            "the fixture must satisfy the latch the defect trusts; otherwise it proves nothing"
        );
        assert_eq!(
            db.sync_state().await.unwrap().peak_height,
            None,
            "the fixture's whole point is a latched replica that never wrote a peak"
        );
        db.upsert_coin(&coin_at_ph("aa", &owned_ph(), 42, Some(1), None))
            .await
            .unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_level_at(REPLICA_PEAK));

        let balance = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        let coins = be
            .coins_for_address(&owned_address(), BalanceAsset::Xch, None, TEST_PAGE)
            .await
            .unwrap();
        let peak = be.chain_peak().await.unwrap();

        assert_eq!(
            balance.peak_height, None,
            "an unknown height must stay unknown; `None` is not height zero"
        );
        assert_eq!(
            balance.balance, 42,
            "the figure is served labelled stale, never withheld"
        );
        assert!(
            !balance.synced,
            "the balance read claimed currency for a replica whose own height it does not know"
        );
        assert_eq!(
            balance.synced, peak.synced,
            "the balance read and `peak` disagreed about one replica at one moment"
        );
        assert_eq!(
            coins.synced, balance.synced,
            "the coin read is the same answer reduced differently and must make the same claim"
        );
    }

    /// **Proves:** the coin read makes the SAME claim as the balance read about the same replica.
    ///
    /// They are the same answer reduced differently, and a caller building a spend reads this one.
    /// A fix applied to only the balance arm would leave the spend path being told a 530-block-old
    /// coin set was current — the more expensive half of the two to be wrong about.
    #[tokio::test]
    async fn the_coin_read_reports_the_same_freshness_as_the_balance_read() {
        let db = db_with_owned_derivation(true, Some(REPLICA_PEAK)).await;
        db.upsert_coin(&coin_at_ph("aa", &owned_ph(), 42, Some(1), None))
            .await
            .unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_ahead_of_the_replica());

        let coins = be
            .coins_for_address(&owned_address(), BalanceAsset::Xch, None, TEST_PAGE)
            .await
            .unwrap();
        assert_eq!(coins.source, Source::Db);
        assert_eq!(coins.coins.len(), 1, "the coin set was withheld");
        assert_eq!(coins.peak_height, Some(REPLICA_PEAK));
        assert!(
            !coins.synced,
            "the spend path was told a stale coin set was current"
        );
    }

    /// The four unspent coins a paging fixture needs, ASCENDING by coin id.
    ///
    /// FOUR, read TWO at a time, so the truncated page and the final page carry the SAME row count
    /// and only one of them is the last. Every length-based inference gives the same answer for
    /// both, which is what makes `complete` load-bearing here rather than decorative.
    const PAGE_FIXTURE: [&str; 4] = ["aa11", "bb22", "cc33", "dd44"];

    async fn db_with_four_unspent_coins() -> WalletDb {
        let db = db_with_owned_derivation(true, Some(REPLICA_PEAK)).await;
        for (i, id) in PAGE_FIXTURE.iter().enumerate() {
            db.upsert_coin(&coin_at_ph(id, &owned_ph(), 10 + i as u64, Some(1), None))
                .await
                .unwrap();
        }
        db
    }

    /// **Proves:** the page boundary survives a coin being SPENT between two pages — no coin is
    /// skipped and none is repeated.
    ///
    /// This is the fixture an OFFSET implementation cannot pass, and the reason the read pages by
    /// cursor. Coin `aa11` is spent after page one is served, so the unspent set shrinks from four
    /// rows to three. An offset of 2 into the shrunken set lands on `dd44` and SKIPS `cc33`
    /// entirely; the cursor `bb22` still names a position, so page two is `cc33` then `dd44`.
    ///
    /// The skipped coin is the whole cost: a caller building a spend never sees it, and refuses
    /// with a shortfall that is not true while the money sits in the coin it could not see. The
    /// assertion is therefore on the coin IDENTITIES and not on the row count — a count-only
    /// assertion would pass against an implementation that returned the wrong two coins.
    ///
    /// Exactly ONE actor varies (the first coin is spent); the other three stay honest, so the
    /// test can still see what a correct implementation returns.
    #[tokio::test]
    async fn a_coin_spent_between_pages_shifts_no_boundary_and_loses_no_coin() {
        let db = db_with_four_unspent_coins().await;
        let be = WalletBackend::new(db.clone(), Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_level_at(REPLICA_PEAK));

        let first = be
            .coins_for_address(&owned_address(), BalanceAsset::Xch, None, 2)
            .await
            .unwrap();
        assert_eq!(
            first.source,
            Source::Db,
            "the fixture must take the DB tier"
        );
        assert_eq!(
            first
                .coins
                .iter()
                .map(|c| c.coin_id.as_str())
                .collect::<Vec<_>>(),
            vec!["aa11", "bb22"],
            "the first page must be the first two coins in ascending coin-id order"
        );
        assert_eq!(first.cursor.as_deref(), Some("bb22"));

        // The event the cursor exists for: a coin BEFORE the boundary leaves the unspent set.
        db.upsert_coin(&coin_at_ph("aa11", &owned_ph(), 10, Some(1), Some(2)))
            .await
            .unwrap();

        let second = be
            .coins_for_address(
                &owned_address(),
                BalanceAsset::Xch,
                first.cursor.as_deref(),
                2,
            )
            .await
            .unwrap();
        assert_eq!(
            second
                .coins
                .iter()
                .map(|c| c.coin_id.as_str())
                .collect::<Vec<_>>(),
            vec!["cc33", "dd44"],
            "a coin was skipped or repeated across the boundary -- an offset-paged read lands on \
             `dd44` alone here, and `cc33` becomes money the caller cannot see"
        );
    }

    /// **Proves:** an exactly-full FINAL page reports `complete: true`, and the truncated page
    /// before it reports `false` while carrying the same number of rows.
    ///
    /// Four coins at a page size of two: both pages hold exactly two. `complete = coins.len() <
    /// limit` calls BOTH of them incomplete, and "a full page means more" calls both truncated, so
    /// this fixture is the one that separates a completeness derived from what REMAINS from one
    /// inferred from length. A spurious `complete: false` on the last page costs one wasted
    /// request; a spurious `true` on the first costs a spend built on half an address's coins.
    #[tokio::test]
    async fn an_exactly_full_final_page_is_complete_and_the_one_before_it_is_not() {
        let db = db_with_four_unspent_coins().await;
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_level_at(REPLICA_PEAK));

        let first = be
            .coins_for_address(&owned_address(), BalanceAsset::Xch, None, 2)
            .await
            .unwrap();
        assert!(
            !first.complete,
            "two of four coins were withheld -- a `true` here presents half an address's holdings \
             as all of them"
        );

        let second = be
            .coins_for_address(
                &owned_address(),
                BalanceAsset::Xch,
                first.cursor.as_deref(),
                2,
            )
            .await
            .unwrap();
        assert_eq!(
            second.coins.len(),
            first.coins.len(),
            "both pages carry the same row count -- which is exactly why length cannot decide it"
        );
        assert!(
            second.complete,
            "the last two coins fit exactly, so this page IS the end of the set"
        );
        assert_eq!(
            second.cursor.as_deref(),
            Some("dd44"),
            "the cursor is the last coin HANDED over, even on a complete page"
        );
    }

    /// **Proves:** walking the pages end to end yields every coin exactly once, in order.
    ///
    /// The composition test the two above cannot replace: each of them looks at one boundary, and
    /// a duplicate or a gap can hide in the seam between three of them. The page size of ONE makes
    /// every coin its own boundary, so every seam is exercised — and it also pins the loop's
    /// termination, since a read that never sets `complete` would spin here rather than pass.
    #[tokio::test]
    async fn a_cursor_walk_visits_every_coin_exactly_once() {
        let db = db_with_four_unspent_coins().await;
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_level_at(REPLICA_PEAK));

        let mut walked: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..PAGE_FIXTURE.len() + 2 {
            let page = be
                .coins_for_address(&owned_address(), BalanceAsset::Xch, cursor.as_deref(), 1)
                .await
                .unwrap();
            walked.extend(page.coins.iter().map(|c| c.coin_id.clone()));
            if page.complete {
                break;
            }
            cursor = page.cursor.clone();
            assert!(
                cursor.is_some(),
                "an incomplete page with no cursor is a walk that cannot continue"
            );
        }
        assert_eq!(
            walked,
            PAGE_FIXTURE
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            "the walk must visit every coin exactly once, in ascending order"
        );
    }

    /// **Proves:** a fallback answer is unchanged — it never borrows the replica's freshness or
    /// its height, however caught-up the replica happens to be.
    #[tokio::test]
    async fn a_fallback_answer_still_claims_neither_freshness_nor_a_height() {
        let db = db_with_owned_derivation(false, Some(REPLICA_PEAK)).await;
        // A LIVE fallback: an unreachable one errors before it can construct an answer, and this
        // test is about the answer's fields.
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_chain_peer_tier_for_tests(peers_ahead_of_the_replica());

        let result = be
            .balance_for_address(&owned_address(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(result.source, Source::Fallback);
        assert!(!result.synced);
        assert_eq!(result.peak_height, None);
    }

    /// **Proves (dig_ecosystem#2869):** an incomplete catch-up NEVER serves from the replica, even
    /// though the replica has a peak height.
    ///
    /// READ THIS BEFORE REMOVING THE `db_synced` AXIS FROM [`routing::route`]. #2869's Scope section
    /// asks for exactly that, on the premise that a behind replica holding the user's coins is not
    /// consulted. The premise does not hold: `db_synced` is `initial_sync_complete`, which latches,
    /// so a behind-but-once-synced replica already routes to [`Source::Db`]. What the axis actually
    /// excludes is a replica that has never finished a catch-up — and that replica holds NOTHING.
    ///
    /// FIXTURE DESIGN — the peak is deliberately PRESENT and the coin table deliberately EMPTY,
    /// which is the exact state measured on the live node (`peak_height = 9140640`,
    /// `initial_sync_complete = 0`, zero coin rows). `new_peak_wallet` advances the peak
    /// independently of any coin being applied, so a present peak is evidence about the CHAIN and
    /// never about this replica's coverage. Serving that state renders to the user as *"Balance: 0,
    /// correct as of block 9,140,640"* for a wallet holding 1.599 XCH — well-formed, precisely
    /// dated, and false. A fixture leaving the peak unset would pass against that implementation
    /// and prove nothing.
    #[tokio::test]
    async fn an_incomplete_catch_up_never_serves_a_dated_zero_from_the_replica() {
        let db = db_with_owned_derivation(false, Some(REPLICA_PEAK)).await;
        assert!(
            !db.is_synced().await.unwrap(),
            "the fixture must be the never-caught-up replica"
        );
        assert_eq!(
            db.sync_state().await.unwrap().peak_height,
            Some(REPLICA_PEAK),
            "the fixture must carry a peak; without one it proves nothing"
        );

        // Anchored to `replica_is_authoritative`, NOT to `db.is_synced()`: dig_ecosystem#2871
        // replaced the latter at both production call sites feeding `route`, so a test still asking
        // `is_synced` would describe a predicate no money read consults — green even if
        // `replica_is_authoritative` started trusting a never-caught-up replica.
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default());
        assert_eq!(
            routing::route(be.replica_is_authoritative().await.unwrap(), true),
            Source::Fallback,
            "a replica with a peak but no completed catch-up was served as authoritative; it holds \
             no coins, so that answer is a dated zero for a funded wallet"
        );
    }

    /// The peak comes from the node's own replica when it has one.
    ///
    /// The peer tier is fixed level with the replica because `synced` is now MEASURED against it
    /// (dig-node#293). This fixture previously ran with an UNOBSERVABLE tier and still asserted
    /// `synced: true` — which is the falsehood #293 removes, so leaving it would have pinned the
    /// defect in place. The subject here is the HEIGHT's provenance; the freshness flag has its
    /// own tests beside the balance reads.
    #[tokio::test]
    async fn the_peak_is_the_replicas_when_the_replica_has_one() {
        let db = db_with_owned_derivation(true, Some(5_000_000)).await;
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_chain_peer_tier_for_tests(peers_level_at(5_000_000));
        assert_eq!(
            be.chain_peak().await.unwrap(),
            ChainPeak {
                peak_height: Some(5_000_000),
                synced: true
            }
        );
    }

    /// **With no replica height and no chain, the peak is UNKNOWN — never zero.**
    ///
    /// The nearest wrong implementation defaults the height to `0`, which every real height is
    /// above, so every "is it buried yet" comparison would silently succeed. This fixture is the
    /// only one that can see that, because it is the only one where no height exists at all.
    #[tokio::test]
    async fn an_unknown_peak_is_none_and_never_zero() {
        let db = db_with_owned_derivation(true, None).await;
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default());
        let peak = be.chain_peak().await.unwrap();
        assert_eq!(peak.peak_height, None);
        assert_ne!(peak.peak_height, Some(0));
        assert!(
            !peak.synced,
            "a height nobody produced is not a synced view"
        );
    }

    /// **Every open chain read that reaches the third-party tier passes the SAME bound.**
    ///
    /// The bound lives inside each method's fallback arm, so "the balance read is limited" says
    /// nothing about the two methods added beside it. This drains the bucket with ONE read and then
    /// asserts the other two are refused — which they can only be if each consults the bound
    /// itself. A method that inherited nothing would answer happily and fail here.
    ///
    /// The peak case is the one that needs a replica with NO height: a node whose replica knows its
    /// peak never reaches the tier at all, so it could not exhibit the property under test.
    #[tokio::test]
    async fn every_open_read_that_leaves_the_node_passes_the_same_rate_bound() {
        let arbitrary = encode_address(&"33".repeat(32), "xch").unwrap();

        // A single token in the bucket, no refill: the first outbound read spends it.
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_fallback_rate_limit(1.0, 0.0);
        assert!(
            be.coins_for_address(&arbitrary, BalanceAsset::Xch, None, TEST_PAGE)
                .await
                .is_ok(),
            "the first read spends the only token"
        );
        assert_eq!(
            be.coins_for_address(&arbitrary, BalanceAsset::Xch, None, TEST_PAGE)
                .await,
            Err(BalanceError::RateLimited),
            "a second coin read must be refused, not amplified onto the third party"
        );

        // The peak read reaches the tier only when the replica has no height of its own.
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_fallback_rate_limit(0.0, 0.0);
        assert_eq!(
            be.chain_peak().await,
            Err(BalanceError::RateLimited),
            "the peak read must consult the bound too"
        );

        // The by-coin reads (dig_ecosystem#2392, #2572). Each forwards a caller-supplied
        // identifier to the third-party oracle on a token-less method, which is precisely the
        // egress-amplification shape the bound exists for.
        //
        // KNOWN LIMITATION, stated so nobody reads more into a green run than it earns: this test
        // ENUMERATES the open reads rather than deriving them, so a NEW read that skips the bucket
        // is not caught here -- it is simply absent. Deriving the list is not possible today
        // because these are inherent methods, not a trait the test could iterate. Adding a read
        // means adding it here.
        for (name, refused) in [
            ("coin_by_id", be.coin_by_id("c1").await.err()),
            ("coin_spend", be.coin_spend("c1").await.err()),
            (
                "coins_by_parent",
                be.coins_by_parent("p", None, 100).await.err(),
            ),
        ] {
            assert_eq!(
                refused,
                Some(BalanceError::RateLimited),
                "{name} must consult the same bound"
            );
        }
    }

    /// **The push actually pushes.** The bundle the pusher receives must be the SAME bundle the hex
    /// described — asserted at the PUSHER, because a client-side check would only prove the client's
    /// own idea of what it sent.
    #[tokio::test]
    async fn an_accepted_push_reaches_the_network_with_the_bundle_it_was_given() {
        let pusher = FakePusher::accepting();
        let db = WalletDb::open_in_memory().await.unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_pusher(pusher.clone());

        let hex = a_signed_bundle_hex();
        let outcome = be.push_signed_bundle(&hex).await.unwrap();

        assert!(outcome.accepted);
        assert!(outcome.rejection.is_none());
        let pushed = pusher.pushed.lock().unwrap();
        assert_eq!(pushed.len(), 1, "exactly one bundle reached the network");
        assert_eq!(
            super::super::chain::encode_signed_bundle(&pushed[0]).unwrap(),
            hex,
            "the bytes pushed must be the bytes signed -- a re-encoded bundle is a DIFFERENT \
             transaction, and the signature would no longer cover it"
        );
    }

    // ---- the node's own money stays behind the live-broadcast flag (18.12) ----------

    use chia_puzzle_types::Memos;
    use chia_sdk_test::Simulator;
    use chia_wallet_sdk::driver::{Cat as SdkCat, Launcher, SpendContext, StandardLayer};
    use chia_wallet_sdk::types::Conditions;

    /// Where every fixture below pays: a puzzle hash nobody in these tests holds a key for.
    const ATTACKER_PH: Bytes32 = Bytes32::new([0x5a; 32]);

    /// A key the node does NOT custody, standing in for a third party whose bundle the node is
    /// asked to relay.
    fn a_stranger() -> BlsPair {
        BlsPair::new(77)
    }

    /// The standard p2 puzzle hash a coin owned by `pk` sits at.
    fn p2_hash(pk: PublicKey) -> Bytes32 {
        Bytes32::from(chia_puzzle_types::standard::StandardArgs::curry_tree_hash(pk).to_bytes())
    }

    /// Render built [`CoinSpend`]s in the JSON form `sign_coin_spends` takes.
    fn as_json(spends: Vec<CoinSpend>) -> Vec<super::super::types::CoinSpendJson> {
        spends
            .iter()
            .map(|cs| super::super::spend::coin_spend_to_json(cs).unwrap())
            .collect()
    }

    /// A BARE standard-layer spend of a coin owned by `pk`, paying [`ATTACKER_PH`].
    ///
    /// The ONLY shape whose coin actually sits at its owner's p2 puzzle hash — which is why a
    /// hash-literal guard looked correct for as long as this was the only fixture.
    fn bare_xch_spend(pk: PublicKey) -> Vec<super::super::types::CoinSpendJson> {
        let ctx = &mut SpendContext::new();
        let coin = Coin::new(Bytes32::new([9u8; 32]), p2_hash(pk), 1_000);
        StandardLayer::new(pk)
            .spend(
                ctx,
                coin,
                Conditions::new().create_coin(ATTACKER_PH, 1_000, Memos::None),
            )
            .unwrap();
        as_json(ctx.take())
    }

    /// A CAT spend of a coin owned by `owner`, paying [`ATTACKER_PH`] — the shape the guard used
    /// to wave through.
    ///
    /// Issued on the simulator so the input CAT is a real coin with real lineage. Its puzzle hash
    /// is `CatArgs::curry_tree_hash(asset_id, owner_p2)`, asserted below rather than assumed,
    /// because the whole finding is that this is NOT the owner's p2 hash.
    fn cat_spend_owned_by(
        sim: &mut Simulator,
        owner: &chia_sdk_test::BlsPairWithCoin,
        signer: &WalletSigner,
    ) -> (Vec<super::super::types::CoinSpendJson>, Bytes32) {
        let ctx = &mut SpendContext::new();
        let p2 = StandardLayer::new(owner.pk);
        let memos = ctx.hint(owner.puzzle_hash).unwrap();
        let (issue, cats) = SdkCat::single_issuance(
            ctx,
            owner.coin.coin_id(),
            // `hidden_puzzle_hash`: the slot chia-sdk-driver 0.36 exposes where 0.30's
            // `issue_with_coin` hard-coded `None`. `None` is the only value that keeps this
            // fixture's CAT identical — it feeds `CatInfo`, so `Some(..)` would change the eve
            // coin's puzzle hash and issue a DIFFERENT coin. The TAIL (and so the asset id) is
            // `GenesisByCoinIdTailArgs` either way.
            None,
            1_000,
            Conditions::new().create_coin(owner.puzzle_hash, 1_000, memos),
        )
        .unwrap();
        p2.spend(ctx, owner.coin, issue).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))
            .unwrap();

        let spends = super::super::spend::build_cat_send(
            signer,
            &[cats[0]],
            ATTACKER_PH,
            1_000,
            owner.puzzle_hash,
            true,
            0,
            &[],
        )
        .unwrap();
        let spent_ph = spends[0].coin.puzzle_hash;
        (as_json(spends), spent_ph)
    }

    /// A SINGLETON spend — a DID owned by `owner`, transferred to [`ATTACKER_PH`].
    ///
    /// Present so the tests assert the property over the CLASS of wrapped puzzles rather than the
    /// one instance the audit happened to find. A DID coin sits at a singleton puzzle hash, which
    /// is a different wrapper from the CAT's and equally unlike the owner's p2 hash.
    fn did_spend_owned_by(
        sim: &mut Simulator,
        owner: &chia_sdk_test::BlsPairWithCoin,
    ) -> (Vec<super::super::types::CoinSpendJson>, Bytes32) {
        let ctx = &mut SpendContext::new();
        let p2 = StandardLayer::new(owner.pk);
        let (create, did) = Launcher::new(owner.coin.coin_id(), 1)
            .create_simple_did(ctx, &p2)
            .unwrap();
        p2.spend(ctx, owner.coin, create).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))
            .unwrap();

        let _child = did
            .transfer(ctx, &p2, ATTACKER_PH, Conditions::new())
            .unwrap();
        let spends = ctx.take();
        let spent_ph = spends[0].coin.puzzle_hash;
        (as_json(spends), spent_ph)
    }

    /// A backend custodying `sk` and nothing else, wired to `pusher`, live broadcast at its
    /// shipped default (OFF).
    ///
    /// Signs for testnet11 because the wrapped fixtures are built on the simulator, whose
    /// consensus verifies the aggregate signature — so a bundle that reaches the guard here is one
    /// the network would really have accepted, not one that merely looks like a spend.
    async fn push_backend(sk: chia_bls::SecretKey, pusher: Arc<FakePusher>) -> WalletBackend {
        let signer = Arc::new(WalletSigner::new(
            vec![sk],
            TESTNET11_CONSTANTS.agg_sig_me_additional_data,
        ));
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let cfg = WalletConfig {
            network_id: "testnet11".into(),
            address_prefix: "txch".into(),
            ..Default::default()
        };
        WalletBackend::new(db, Arc::new(MockFallback::default()), cfg)
            .with_signer(signer)
            .with_pusher(pusher)
    }

    /// Sign `coin_spends` through `be`'s OWN custodied key WITHOUT submitting, and return the
    /// bundle in the hex form `control.wallet.broadcast` accepts.
    ///
    /// This is the attacker's chain, verbatim: `sign_coin_spends {auto_submit:false}` ->
    /// hex-encode the returned bundle -> push. Written as a helper so the tests below cannot
    /// accidentally push a bundle the node did NOT sign, which would prove nothing.
    async fn signed_by_the_node(
        be: &WalletBackend,
        coin_spends: Vec<super::super::types::CoinSpendJson>,
    ) -> String {
        let signed = be
            .sign_coin_spends(&SignCoinSpends {
                coin_spends,
                auto_submit: false,
                partial: false,
            })
            .await
            .expect("the node signs with its own custodied key on request");
        super::super::chain::encode_signed_bundle(
            &super::super::spend::spend_bundle_from_json(&signed.spend_bundle).unwrap(),
        )
        .unwrap()
    }

    /// **A bundle signed by the NODE's own key cannot be pushed while live broadcast is off.**
    ///
    /// The chain this closes: a token holder calls `sign_coin_spends {auto_submit:false}`, gets a
    /// fully-signed bundle spending the node's coins, hex-encodes it, and hands it back to
    /// `control.wallet.broadcast`. Every step is individually permitted, and together they send the
    /// node's own money with `DIG_WALLET_ENABLE_LIVE_BROADCAST` off.
    ///
    /// The SECOND bundle is the control that makes this test load-bearing: it is signed by the same
    /// node, over the same surface, on the same backend, and differs ONLY in whose puzzle hash the
    /// coin sits at. A guard that simply refused every push while the flag is off -- which would
    /// break the capability this method exists for -- fails on it. Both are asserted at the PUSHER,
    /// so a refusal that still leaked bytes onto the network would be visible.
    #[tokio::test]
    async fn the_nodes_own_signed_spend_is_refused_while_live_broadcast_is_off() {
        let node = BlsPair::new(1);
        let pusher = FakePusher::accepting();
        let be = push_backend(node.sk.clone(), pusher.clone()).await;
        assert!(
            !be.node_custodied_spending,
            "the shipped default is OFF -- if this ever flips, this whole test is vacuous"
        );

        let own = signed_by_the_node(&be, bare_xch_spend(node.pk)).await;
        assert_eq!(
            be.push_signed_bundle(&own).await,
            Err(PushError::NodeCustodiedSpend),
            "the node must not relay a spend of its OWN coins with live broadcast off"
        );

        let somebody_else = signed_by_the_node(&be, bare_xch_spend(a_stranger().pk)).await;
        assert!(
            be.push_signed_bundle(&somebody_else).await.is_ok(),
            "relaying a bundle over somebody ELSE's coins is the capability this method adds, and \
             must stay open on every install"
        );

        let pushed = pusher.pushed.lock().unwrap();
        assert_eq!(
            pushed.len(),
            1,
            "exactly one bundle reached the network -- the refused one must not have leaked"
        );
        assert_eq!(
            super::super::chain::encode_signed_bundle(&pushed[0]).unwrap(),
            somebody_else,
            "and it must be the third-party bundle, not the node's own"
        );
    }

    /// **The node's own CAT is refused too — the coin the guard used to wave through.**
    ///
    /// The node holds real $DIG, which is a CAT, and that is the whole reason the tipping
    /// subsystem exists. A CAT coin does NOT sit at its owner's p2 puzzle hash: it sits at
    /// `CatArgs::curry_tree_hash(asset_id, p2_hash)`. `WalletSigner::sign` never looks at the
    /// puzzle hash — it matches the required BLS key — so the node signed this bundle happily
    /// while a hash-literal guard saw an unfamiliar coin and relayed it, sending the node's $DIG
    /// with `DIG_WALLET_ENABLE_LIVE_BROADCAST` off.
    ///
    /// The fixture asserts the divergence it depends on rather than assuming it: if the spent
    /// coin's puzzle hash ever equalled the node's p2 hash, the old guard would have caught this
    /// and the test would prove nothing.
    #[tokio::test]
    async fn the_nodes_own_cat_spend_is_refused_though_the_coin_is_not_at_its_puzzle_hash() {
        let mut sim = Simulator::new();
        let node = sim.bls(1_000);
        let pusher = FakePusher::accepting();
        let be = push_backend(node.sk.clone(), pusher.clone()).await;

        let signer = WalletSigner::new(
            vec![node.sk.clone()],
            TESTNET11_CONSTANTS.agg_sig_me_additional_data,
        );
        let (spends, spent_ph) = cat_spend_owned_by(&mut sim, &node, &signer);
        assert_ne!(
            spent_ph,
            p2_hash(node.pk),
            "the CAT must not sit at the node's own p2 hash, or this fixture cannot see the bug"
        );

        let own = signed_by_the_node(&be, spends).await;
        assert_ne!(
            super::super::chain::decode_signed_bundle(&own)
                .unwrap()
                .aggregated_signature,
            chia_bls::Signature::default(),
            "the node really signed it -- an unsigned bundle would refute nothing"
        );
        assert_eq!(
            be.push_signed_bundle(&own).await,
            Err(PushError::NodeCustodiedSpend),
            "a CAT the node can sign for is the node's own money, wherever the coin sits"
        );
        assert!(
            pusher.pushed.lock().unwrap().is_empty(),
            "the refused bundle must not have leaked onto the network"
        );
    }

    /// **A SINGLETON the node owns is refused on the same rule** — the property holds over the
    /// CLASS of wrapped puzzles, not just the CAT instance the audit happened to find.
    ///
    /// A DID coin sits at a singleton puzzle hash: a different wrapper from the CAT's, equally
    /// unlike the owner's p2 hash, and equally signable by the node. A guard patched by adding
    /// CAT-wrapped hashes to a hash set would pass the CAT test above and fail here — which is
    /// exactly why the fix asks the signer's own question instead.
    #[tokio::test]
    async fn a_singleton_the_node_owns_is_refused_on_the_same_rule() {
        let mut sim = Simulator::new();
        let node = sim.bls(2);
        let pusher = FakePusher::accepting();
        let be = push_backend(node.sk.clone(), pusher.clone()).await;

        let (spends, spent_ph) = did_spend_owned_by(&mut sim, &node);
        assert_ne!(
            spent_ph,
            p2_hash(node.pk),
            "a singleton does not sit at its owner's p2 hash either"
        );

        let own = signed_by_the_node(&be, spends).await;
        assert_eq!(
            be.push_signed_bundle(&own).await,
            Err(PushError::NodeCustodiedSpend),
            "every puzzle wrapper over the node's key is still the node's money"
        );
        assert!(pusher.pushed.lock().unwrap().is_empty());
    }

    /// **A restarted, still-LOCKED node refuses a bundle over a key beyond its receive address.**
    ///
    /// The memo of loaded signers lives in the process, so a restart empties it and the guard falls
    /// back to what the custody manifest persisted. When that was the receive ADDRESS, the fallback
    /// covered HD index 0 alone while the signer covers `0..derivation_count` — so a bundle
    /// pre-signed over the wallet's index-1 coin passed a guard whose own signer would have signed
    /// it. Persisting the public keys closes that, because keys enumerate where wrapped puzzle
    /// hashes do not.
    ///
    /// The fixture deliberately uses the NON-primary key: an index-0 bundle is caught by the
    /// address fallback too, so it could not tell the two implementations apart.
    #[tokio::test]
    async fn a_restarted_locked_node_still_refuses_a_bundle_over_its_non_primary_key() {
        // Owned by the guard, so the tree goes away on drop and on an unwind (dig-node#370).
        let dir = tempfile::Builder::new()
            .prefix("dig-wallet-restart-guard-")
            .tempdir()
            .expect("a scratch dir");

        // The wallet as a pre-#1701 install left it: two HD keys persisted in the manifest, the
        // seed unreadable. `primary` stands for the receive address the old fallback covered;
        // `secondary` is the key beyond it, and is what the bundle spends.
        let primary = BlsPair::new(41);
        let secondary = BlsPair::new(42);
        assert_ne!(
            p2_hash(primary.pk),
            p2_hash(secondary.pk),
            "the fixture needs two DISTINCT keys, or it cannot tell the two guards apart"
        );
        WalletCustody::enroll_for_tests(dir.path(), "restart-fixture", &[primary.pk, secondary.pk]);

        let pusher = FakePusher::accepting();
        let cfg = WalletConfig {
            network_id: "testnet11".into(),
            address_prefix: "txch".into(),
            ..Default::default()
        };

        // Sign over the SECONDARY key. Signing needs a signer, which only the simulator path can
        // attach now (§908) — and it is the right shape either way: the bundle arrives pre-signed
        // from somewhere else, which is exactly the push the guard has to catch.
        let signing = push_backend(secondary.sk.clone(), pusher.clone()).await;
        let own = signed_by_the_node(&signing, bare_xch_spend(secondary.pk)).await;

        // Restart: a fresh custody over the SAME directory and a fresh backend whose memo of
        // loaded signers is empty.
        let restarted = WalletCustody::open(dir.path().to_path_buf());
        let db2 = WalletDb::open_in_memory().await.unwrap();
        db2.force_initial_sync_complete_for_test(true)
            .await
            .unwrap();
        let after = WalletBackend::new(db2, Arc::new(MockFallback::default()), cfg)
            .with_custody(restarted)
            .with_pusher(pusher.clone());
        assert!(
            after.current_signer().is_none(),
            "the restarted node must hold no signer, or the manifest fallback is never exercised"
        );

        assert_eq!(
            after.push_signed_bundle(&own).await,
            Err(PushError::NodeCustodiedSpend),
            "a locked node still custodies every key in its derivation range"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A bundle that spends the node's coins ALONGSIDE somebody else's is still refused.**
    ///
    /// The nearest wrong implementation checks only the FIRST coin spend, or asks whether the
    /// bundle is *entirely* the node's. Either reads the node's money out through one extra spend,
    /// so the fixture puts the node's coin SECOND behind a third party's.
    #[tokio::test]
    async fn a_mixed_bundle_touching_the_nodes_coins_is_refused_too() {
        let node = BlsPair::new(1);
        let be = push_backend(node.sk.clone(), FakePusher::accepting()).await;
        let mut spends = bare_xch_spend(a_stranger().pk);
        spends.extend(bare_xch_spend(node.pk));
        let mixed = signed_by_the_node(&be, spends).await;
        assert_eq!(
            be.push_signed_bundle(&mixed).await,
            Err(PushError::NodeCustodiedSpend),
            "one spend of the node's coins is enough to refuse the whole bundle"
        );
    }

    /// **The refusal survives the signer being dropped**, which is the DEFAULT custody mode.
    ///
    /// Under 18.24 per-transaction re-auth the one-shot grant is consumed by the signature, so by
    /// the time the caller pushes, `current_signer()` is `None` and the live signer's hashes are
    /// unreachable. This reproduces exactly that: sign, then drop the signer, then push.
    ///
    /// Without the memo this test is the one that fails while every other guard test still passes --
    /// the guard would consult an empty set on precisely the path it was written to stop.
    #[tokio::test]
    async fn the_refusal_survives_the_signing_grant_expiring() {
        let node = BlsPair::new(1);
        let be = push_backend(node.sk.clone(), FakePusher::accepting()).await;
        let own = signed_by_the_node(&be, bare_xch_spend(node.pk)).await;

        // The grant is gone: no signer resolves any more, exactly as after a one-shot sign. The
        // config's watched puzzle hashes are cleared with it, so the only thing that can still
        // recognise the coin is the memo. The default config also flips the network back to
        // mainnet, which changes the MESSAGE each signature commits to -- and must not change
        // which KEY the guard sees required.
        let relocked = WalletBackend {
            signer: None,
            config: WalletConfig::default(),
            ..be.clone()
        };
        assert!(
            relocked.current_signer().is_none(),
            "the fixture must actually be signer-less, or it proves nothing"
        );
        assert_eq!(
            relocked.push_signed_bundle(&own).await,
            Err(PushError::NodeCustodiedSpend),
            "a bundle the node signed a moment ago is still the node's own money"
        );
    }

    /// **With live broadcast ON, the node's own signed spend pushes.**
    ///
    /// The guard must be the FLAG's answer, not a permanent refusal. Same backend, same bundle,
    /// one field different -- so a hardcoded "always refuse the node's coins" fails here.
    #[tokio::test]
    async fn the_nodes_own_signed_spend_pushes_when_live_broadcast_is_on() {
        let node = BlsPair::new(1);
        let pusher = FakePusher::accepting();
        let be = push_backend(node.sk.clone(), pusher.clone())
            .await
            .with_node_custodied_spending(true);
        let own = signed_by_the_node(&be, bare_xch_spend(node.pk)).await;
        assert!(
            be.push_signed_bundle(&own).await.unwrap().accepted,
            "with the flag on, the node's own send is exactly what is being enabled"
        );
        assert_eq!(pusher.pushed.lock().unwrap().len(), 1);
    }

    /// **A mempool refusal is a VALUE; an unreachable mempool is an ERROR.**
    ///
    /// Both cases push the SAME well-formed bundle through the SAME code path and vary only what
    /// the network said, so an implementation that routed a refusal onto the error channel — where
    /// it is indistinguishable from an outage — fails here.
    #[tokio::test]
    async fn a_refusal_and_an_outage_are_different_answers() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let refused = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_pusher(FakePusher::answering(Ok(PushOutcome {
                accepted: false,
                transaction_id: None,
                rejection: Some("DOUBLE_SPEND".into()),
                verdict: "FAILED".into(),
            })));
        let outcome = refused
            .push_signed_bundle(&a_signed_bundle_hex())
            .await
            .expect("a refusal is a successful call");
        assert!(!outcome.accepted);
        assert_eq!(outcome.rejection.as_deref(), Some("DOUBLE_SPEND"));

        let db = WalletDb::open_in_memory().await.unwrap();
        let offline = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_pusher(FakePusher::answering(Err("connection reset".into())));
        assert!(matches!(
            offline.push_signed_bundle(&a_signed_bundle_hex()).await,
            Err(PushError::Unreachable(_))
        ));
    }

    /// A node with no pusher says so, rather than reporting an acceptance it never obtained.
    #[tokio::test]
    async fn a_node_that_cannot_push_never_reports_an_acceptance() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default());
        assert_eq!(
            be.push_signed_bundle(&a_signed_bundle_hex()).await,
            Err(PushError::NoChainSource)
        );
    }

    /// Garbage is rejected BEFORE any network call, because retrying it can never help.
    #[tokio::test]
    async fn a_malformed_bundle_is_refused_without_touching_the_network() {
        let pusher = FakePusher::accepting();
        let db = WalletDb::open_in_memory().await.unwrap();
        let be = WalletBackend::new(db, Arc::new(EmptyFallback), WalletConfig::default())
            .with_pusher(pusher.clone());
        assert!(matches!(
            be.push_signed_bundle("not-hex").await,
            Err(PushError::InvalidBundle(_))
        ));
        assert!(
            pusher.pushed.lock().unwrap().is_empty(),
            "nothing may be sent for a bundle that cannot be parsed"
        );
    }

    // ---- #1957: the coinset-fallback path is abuse-bounded -----------------------------------

    /// A fresh arbitrary address for a sweep — each derived from a distinct seed byte so no two
    /// reads collapse onto one puzzle hash.
    fn arbitrary_address(seed: u8) -> String {
        encode_address(&format!("{seed:02x}").repeat(32), "xch").unwrap()
    }

    /// A rapid SWEEP of arbitrary addresses that force the coinset fallback trips the global
    /// rate bound: with a fixed pool of `N` fallback tokens (no refill), the first `N` reads
    /// succeed and the `(N+1)`th is refused with the distinct [`BalanceError::RateLimited`].
    /// RED without a limiter: every read would succeed.
    #[tokio::test]
    async fn wallet_balance_fallback_is_rate_limited_after_a_burst() {
        const POOL: usize = 4;
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_fallback_rate_limit(POOL as f64, 0.0); // no refill ⇒ deterministic

        for i in 0..POOL {
            let r = be
                .balance_for_address(&arbitrary_address(i as u8), BalanceAsset::Xch)
                .await;
            assert!(r.is_ok(), "read {i} within the burst is admitted: {r:?}");
        }
        assert_eq!(
            be.balance_for_address(&arbitrary_address(0xEE), BalanceAsset::Xch)
                .await,
            Err(BalanceError::RateLimited),
            "the read past the burst is refused with the rate-limit error"
        );
    }

    /// A SINGLE legitimate fallback read is never throttled — the limiter must not trip on one.
    /// RED if the bound were set below 1 (too aggressive).
    #[tokio::test]
    async fn a_single_legitimate_balance_read_is_unaffected() {
        let arb_ph = "44".repeat(32);
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let fb = Arc::new(MockFallback::with_coins(vec![fallback_coin(
            "c1",
            &arb_ph,
            77,
            Some(10),
            None,
        )]));
        // Even a minimal pool of exactly one token admits the single honest read.
        let be =
            WalletBackend::new(db, fb, WalletConfig::default()).with_fallback_rate_limit(1.0, 0.0);
        let r = be
            .balance_for_address(&encode_address(&arb_ph, "xch").unwrap(), BalanceAsset::Xch)
            .await
            .unwrap();
        assert_eq!(r.balance, 77, "the honest read returns its real figure");
    }

    /// The cheap, legitimate local-DB fast path is NEVER rate-limited: even with a fully
    /// exhausted (zero-capacity) fallback bucket, a burst of DB-hit reads all succeed, proving
    /// the gate sits ONLY in front of the fallback, not ahead of the DB fast path. RED if the
    /// limiter were placed before the routing decision.
    #[tokio::test]
    async fn the_local_db_fast_path_is_not_rate_limited() {
        let db = db_with_owned_derivation(true, Some(10)).await;
        db.upsert_coins(&[coin_at_ph("confirmed", &owned_ph(), 100, Some(10), None)])
            .await
            .unwrap();
        // A zero-token bucket would refuse ANY fallback call — but the DB path must bypass it.
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_fallback_rate_limit(0.0, 0.0);
        for _ in 0..10 {
            let r = be
                .balance_for_address(&owned_address(), BalanceAsset::Xch)
                .await
                .expect("the DB fast path is never throttled");
            assert_eq!(r.balance, 100);
        }
    }

    // ---- the limiter sits BELOW the chain-read cache (dig_ecosystem#3044) -------------

    /// One generation of a lineage: a coin, spent, plus the spend that spent it.
    fn generation(id: &str, spent_at: u32) -> (FallbackCoin, FallbackCoinSpend) {
        (
            fallback_coin(id, &owned_ph(), 100, Some(spent_at - 1), Some(spent_at)),
            fallback_spend(id),
        )
    }

    /// **A lineage walk served entirely from cache spends ZERO rate-limit tokens.**
    ///
    /// The bucket here is EMPTY and never refills, so every token the walk might take is a token it
    /// cannot have: the walk completes only if it takes none. That is what pins the ORDERING rather
    /// than the tuning — a limiter left above the cache with a larger burst passes a
    /// "more reads succeed now" test and fails this one, at any capacity.
    ///
    /// The network side of the double is EMPTY and its call counter is asserted at zero, so a read
    /// that reached past the cache could not have produced these answers.
    ///
    /// **Catches** the shipped defect: with the gate above the cache, a client polling the same
    /// coins drains the bucket with reads that send nothing, and the profile read it is polling FOR
    /// can never be afforded again (the measured equilibrium on dig_ecosystem#3044).
    #[tokio::test]
    async fn a_walk_served_entirely_from_cache_spends_no_rate_limit_tokens() {
        let (g0, s0) = generation("gen-0", 40);
        let (g1, s1) = generation("gen-1", 41);
        let (g2, s2) = generation("gen-2", 42);
        let fb = Arc::new(MockFallback::default().with_cached(vec![g0, g1, g2], vec![s0, s1, s2]));
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb.clone(),
            WalletConfig::default(),
        )
        .with_fallback_rate_limit(0.0, 0.0);

        for id in ["gen-0", "gen-1", "gen-2"] {
            let coin = be
                .coin_by_id(id)
                .await
                .unwrap_or_else(|e| panic!("the cached record for {id} needs no token: {e:?}"));
            assert_eq!(coin.coin.expect("the cached coin is served").coin_id, id);
            let spend = be
                .coin_spend(id)
                .await
                .unwrap_or_else(|e| panic!("the cached spend for {id} needs no token: {e:?}"));
            assert_eq!(
                spend
                    .spend
                    .expect("the cached spend is served")
                    .coin
                    .coin_id,
                id
            );
        }
        assert_eq!(
            fb.call_count(),
            0,
            "a cache-served walk reaches the network zero times — so it bounds no egress"
        );
    }

    /// **The bound it exists for is UNCHANGED: a cache MISS still costs a token.**
    ///
    /// The control for the test above, and the one that would catch "the fix" implemented as
    /// deleting the gate. One token, two misses: the first is admitted, the second refused.
    #[tokio::test]
    async fn a_cache_miss_still_spends_a_token_and_is_refused_once_the_bucket_is_empty() {
        let (g0, _) = generation("miss-0", 40);
        let (g1, _) = generation("miss-1", 41);
        let fb = Arc::new(MockFallback::with_coins(vec![g0, g1]));
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb.clone(),
            WalletConfig::default(),
        )
        .with_fallback_rate_limit(1.0, 0.0);

        assert!(
            be.coin_by_id("miss-0").await.is_ok(),
            "the first miss is admitted and spends the one token"
        );
        assert_eq!(
            be.coin_by_id("miss-1").await,
            Err(BalanceError::RateLimited),
            "the second miss finds the bucket empty: egress is still bounded"
        );
        assert_eq!(
            fb.call_count(),
            1,
            "exactly the admitted miss reached the network"
        );
    }

    /// **A COLD multi-generation walk completes on the default bound.**
    ///
    /// Six generations is eleven reads — six records and five spends — against the shipped burst of
    /// [`DEFAULT_FALLBACK_BURST`]. Nothing is cached, so every read is a real one, and none may be
    /// refused: a lineage walk that cannot afford its own first pass never populates the cache the
    /// test above then serves from.
    #[tokio::test]
    async fn a_cold_multi_generation_walk_completes_without_a_rate_limit_refusal() {
        const GENERATIONS: u32 = 6;
        let mut coins = Vec::new();
        let mut spends = Vec::new();
        for i in 0..GENERATIONS {
            let (coin, spend) = generation(&format!("cold-{i}"), 40 + i);
            coins.push(coin);
            // The last generation is the TIP: it is spent nowhere, so no spend is read for it.
            if i + 1 < GENERATIONS {
                spends.push(spend);
            }
        }
        let fb = Arc::new(MockFallback::with_coins(coins).with_spends(spends));
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb.clone(),
            WalletConfig::default(),
        );

        for i in 0..GENERATIONS {
            let id = format!("cold-{i}");
            assert!(
                be.coin_by_id(&id).await.is_ok(),
                "generation {i}'s record is affordable on the default bound"
            );
            if i + 1 < GENERATIONS {
                assert!(
                    be.coin_spend(&id).await.is_ok(),
                    "generation {i}'s spend is affordable on the default bound"
                );
            }
        }
    }

    // ---- a cache HIT needs no live fallback either (dig_ecosystem#3050) --------------

    /// A double whose chain tier is DOWN but whose cache holds one full generation — the state a
    /// transient outage produces on a node that has already walked this lineage.
    fn offline_with_cached_generation(id: &str) -> Arc<MockFallback> {
        let (coin, spend) = generation(id, 40);
        Arc::new(
            MockFallback::default()
                .with_cached(vec![coin], vec![spend])
                .offline(),
        )
    }

    /// **`coin_by_id` serves a cached record while the chain tier is unreachable.**
    ///
    /// The double is `offline()` — `is_live()` is false, so nothing networked can answer — and its
    /// cache is populated. The read succeeds only if the cached arm never consults liveness.
    ///
    /// **Catches** the shipped ordering: with `is_live()` above the cache, a node holding every
    /// byte of the answer refuses it because a third party is momentarily unreachable. Measured
    /// under revert: `NoChainSource`.
    ///
    /// Deliberately SEPARATE from the `coin_spend` test below rather than two assertions in one
    /// body: the first `expect` to fire ends the test, so a combined test would prove only whichever
    /// arm it probed first and pass the other for free.
    #[tokio::test]
    async fn coin_by_id_serves_a_cached_record_while_the_chain_tier_is_unreachable() {
        let fb = offline_with_cached_generation("down-0");
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb.clone(),
            WalletConfig::default(),
        );

        let coin = be
            .coin_by_id("down-0")
            .await
            .expect("a cached record needs no live source: the answer is already in hand");
        assert_eq!(
            coin.coin.expect("the cached coin is served").coin_id,
            "down-0"
        );
        assert_eq!(
            fb.call_count(),
            0,
            "an offline double could not have answered this over the wire"
        );
    }

    /// **`coin_spend` serves a fully-cached spend while the chain tier is unreachable.**
    ///
    /// The `coin_spend` half of the arm above, pinned independently for the reason stated there.
    /// BOTH halves of the composition are cached here, so this is a true hit; the partially-cached
    /// case is a miss and is pinned separately below.
    ///
    /// Measured under revert: `NoChainSource`.
    #[tokio::test]
    async fn coin_spend_serves_a_cached_spend_while_the_chain_tier_is_unreachable() {
        let fb = offline_with_cached_generation("down-1");
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb.clone(),
            WalletConfig::default(),
        );

        let spend = be
            .coin_spend("down-1")
            .await
            .expect("a cached spend needs no live source either");
        assert_eq!(
            spend
                .spend
                .expect("the cached spend is served")
                .coin
                .coin_id,
            "down-1"
        );
        assert_eq!(
            fb.call_count(),
            0,
            "an offline double could not have answered this over the wire"
        );
    }

    /// **A cache MISS with no live source is still an ERROR, never an absence.**
    ///
    /// The control for the test above, and the one that catches "the fix" implemented as deleting
    /// the liveness check. `Ok(None)` here would collapse "I could not check" into "it does not
    /// exist" — which a lineage walk reads as *this coin is the tip*.
    #[tokio::test]
    async fn a_cache_miss_with_no_live_source_is_refused_rather_than_answered_empty() {
        let fb = Arc::new(MockFallback::default().offline());
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb.clone(),
            WalletConfig::default(),
        );

        assert_eq!(
            be.coin_by_id("absent").await,
            Err(BalanceError::NoChainSource),
            "an uncached coin with nothing to ask is UNKNOWN, not absent"
        );
        assert_eq!(
            be.coin_spend("absent").await,
            Err(BalanceError::NoChainSource),
            "an uncached spend with nothing to ask is UNKNOWN, not unspent"
        );
    }

    /// **A PARTIALLY cached spend is a genuine miss: it keeps the liveness check.**
    ///
    /// The composition the #3044 lane documented, pinned. The spend is cached; its coin RECORD is
    /// not — and the record is where the heights come from, so answering still requires reaching a
    /// peer. That makes this case a miss, and a miss with no live source must refuse rather than
    /// emit a spend with an absent `spent_height`.
    ///
    /// Without this the obvious over-correction — hoisting the whole cached arm above `is_live()`
    /// and treating a half-hit as a hit — passes the test above and ships an invented height.
    #[tokio::test]
    async fn a_spend_cached_without_its_record_still_requires_a_live_source() {
        let (_, s0) = generation("half-0", 40);
        let fb = Arc::new(
            MockFallback::default()
                .with_cached(vec![], vec![s0])
                .offline(),
        );
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            fb.clone(),
            WalletConfig::default(),
        );

        assert_eq!(
            be.coin_spend("half-0").await,
            Err(BalanceError::NoChainSource),
            "the heights live in the record, which is NOT cached: this read still needs a peer"
        );
        assert_eq!(fb.call_count(), 0, "and it never reached one");
    }

    #[tokio::test]
    async fn get_version_reports_crate_version() {
        let be = backend_with(vec![], true).await;
        let (status, body) = be.dispatch("get_version", "{}").await;
        assert_eq!(status, 200);
        assert!(body.contains(env!("CARGO_PKG_VERSION")));
    }

    #[tokio::test]
    async fn synced_get_coins_reads_from_db_not_fallback() {
        let fb = Arc::new(MockFallback::default());
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[
            xch_coin("c1", 100, Some(10), None),
            xch_coin("c2", 50, Some(11), Some(12)),
        ])
        .await
        .unwrap();
        // A catch-up that COVERED the scope these reads use, not merely a flag saying one
        // finished — the identity-scoped router asks about coverage (dig_ecosystem#2878).
        db.record_coverage(&CoveredSet::from_hex([test_ph()]))
            .await
            .unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        // Reads scope to the wallet's identity (#407); the test coins sit at `test_ph()`.
        let cfg = WalletConfig {
            puzzle_hashes: vec![test_ph()],
            ..Default::default()
        };
        let be = WalletBackend::new(db, fb.clone(), cfg);

        let (status, body) = be.dispatch("get_coins", r#"{"offset":0,"limit":10}"#).await;
        assert_eq!(status, 200);
        let resp: GetCoinsResponse = serde_json::from_str(&body).unwrap();
        // Default filter is Selectable → only the unspent coin.
        assert_eq!(resp.coins.len(), 1);
        assert_eq!(resp.coins[0].coin_id, "c1");
        assert_eq!(
            fb.call_count(),
            0,
            "synced reads must NOT touch the fallback"
        );
    }

    #[tokio::test]
    async fn syncing_get_coins_routes_to_fallback() {
        let ph = "11".repeat(32);
        let fb = Arc::new(MockFallback::with_coins(vec![FallbackCoin {
            coin_id: "fc1".into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: ph.clone(),
            amount: 777,
            created_height: Some(5),
            spent_height: None,
            created_timestamp: None,
            spent_timestamp: None,
        }]));
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(false)
            .await
            .unwrap(); // still syncing
        let cfg = WalletConfig {
            puzzle_hashes: vec![ph],
            ..Default::default()
        };
        let be = WalletBackend::new(db, fb.clone(), cfg);

        let (status, body) = be.dispatch("get_coins", r#"{"offset":0,"limit":10}"#).await;
        assert_eq!(status, 200);
        let resp: GetCoinsResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.coins.len(), 1);
        assert_eq!(resp.coins[0].coin_id, "fc1");
        assert!(
            fb.call_count() >= 1,
            "syncing reads must consult the fallback"
        );
    }

    #[tokio::test]
    async fn out_of_db_coin_id_falls_back_when_synced() {
        let fb = Arc::new(MockFallback::with_coins(vec![FallbackCoin {
            coin_id: "external".into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: "22".repeat(32),
            amount: 9,
            created_height: Some(3),
            spent_height: None,
            created_timestamp: None,
            spent_timestamp: None,
        }]));
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[xch_coin("inwallet", 1, Some(1), None)])
            .await
            .unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(db, fb.clone(), WalletConfig::default());

        let (status, body) = be
            .dispatch(
                "get_coins_by_ids",
                r#"{"coin_ids":["inwallet","external"]}"#,
            )
            .await;
        assert_eq!(status, 200);
        let resp: GetCoinsByIdsResponse = serde_json::from_str(&body).unwrap();
        let ids: Vec<_> = resp.coins.iter().map(|c| c.coin_id.as_str()).collect();
        assert!(ids.contains(&"inwallet"));
        assert!(
            ids.contains(&"external"),
            "an out-of-DB id must be served from the fallback"
        );
        assert!(fb.call_count() >= 1);
    }

    #[tokio::test]
    async fn unknown_method_is_404() {
        let be = backend_with(vec![], true).await;
        // `get_secret_key` is a real Sage endpoint but not served here (secret-touching,
        // never exposed) — an unsupported method → 404.
        let (status, body) = be.dispatch("get_secret_key", "{}").await;
        assert_eq!(status, 404);
        assert!(body.contains("unsupported"));
    }

    #[tokio::test]
    async fn malformed_request_is_400() {
        let be = backend_with(vec![], true).await;
        let (status, _body) = be.dispatch("get_coins", "{ not json").await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn get_sync_status_reports_balance_and_gate() {
        let be = backend_with(vec![xch_coin("c1", 12_000, Some(10), None)], true).await;
        let (status, body) = be.dispatch("get_sync_status", "{}").await;
        assert_eq!(status, 200);
        let resp: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.selectable_balance.to_u64(), Some(12_000));
        assert_eq!(resp.unit.ticker, "XCH");
    }

    #[tokio::test]
    async fn is_asset_owned_reflects_db() {
        let mut c = xch_coin("cat", 5, Some(1), None);
        c.asset_id = Some("dead".into());
        let be = backend_with(vec![c], true).await;
        let (_s, body) = be
            .dispatch("is_asset_owned", r#"{"asset_id":"dead"}"#)
            .await;
        let resp: IsAssetOwnedResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.owned);
    }

    // ---- send/spend dispatch (#216) --------------------------------------

    use super::super::db::NftDbRow;
    use super::super::spend::{
        BroadcastConsent, ConsentBroadcaster, MockBroadcaster, WalletSigner,
    };
    use chia_sdk_test::BlsPair;

    /// A backend with a signer over a single test key, a coin funded at that key's puzzle
    /// hash, and a mock broadcaster — enough to drive the send/spend surface off-chain.
    async fn spend_backend(fund: u64) -> (WalletBackend, std::sync::Arc<MockBroadcaster>, Bytes32) {
        let pair = BlsPair::new(1);
        let signer = Arc::new(WalletSigner::new(vec![pair.sk], Bytes32::new([0u8; 32])));
        let ph = *signer.puzzle_hashes().iter().next().unwrap();
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&CoinRow {
            coin_id: "coin1".into(),
            parent_coin_info: "11".repeat(32),
            puzzle_hash: hex::encode(ph),
            amount: fund.to_string(),
            created_height: Some(1),
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        })
        .await
        .unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let bc = Arc::new(MockBroadcaster::default());
        let cfg = WalletConfig {
            puzzle_hashes: vec![hex::encode(ph)],
            address_prefix: "txch".into(),
            ..Default::default()
        };
        let be = WalletBackend::new(db, Arc::new(MockFallback::default()), cfg)
            .with_signer(signer)
            .with_broadcaster(bc.clone());
        (be, bc, ph)
    }

    // ---- F2: the spend path is tier-gated like every other wallet read --------------------

    /// **Proves (F2, #2501 re-audit):** coins a peer put in the local table cannot fund a spend
    /// while the replica is not authoritative - at BOTH hops, the input reader and the RPC that
    /// calls it.
    ///
    /// The fixture is the auditor's: FIFTY fabricated coins at the wallet's own puzzle hash,
    /// which is exactly the shape the subscription filter cannot catch, because the wallet HANDS
    /// the peer that hash. They are worth 50 XCH, so a run that selects them is unmistakable.
    ///
    /// Two hops, deliberately. This defect is a PLACEMENT - the gate existed in
    /// [`routing::route`] and the spend readers simply never called it - so a test that only
    /// drove `send_xch` would stay green if the guard were later moved somewhere that leaves
    /// `spendable_coins` open to its other callers (offers, mint, the node-custodied tip spend).
    /// The control at the end flips ONLY the authority flag and shows the very same rows
    /// becoming selectable, so the test cannot be passed by a backend that is simply broken.
    #[tokio::test]
    async fn fabricated_coins_cannot_fund_a_spend_from_an_unauthoritative_replica() {
        let pair = BlsPair::new(3);
        let signer = Arc::new(WalletSigner::new(vec![pair.sk], Bytes32::new([0u8; 32])));
        let ph = *signer.puzzle_hashes().iter().next().unwrap();
        let ph_hex = hex::encode(ph);

        let fabricated: Vec<CoinRow> = (0..50)
            .map(|i| CoinRow {
                coin_id: format!("{i:064x}"),
                parent_coin_info: "11".repeat(32),
                puzzle_hash: ph_hex.clone(),
                amount: 1_000_000_000_000u64.to_string(),
                created_height: Some(5),
                spent_height: None,
                asset_id: None,
                hint: None,
                created_timestamp: Some(1),
                spent_timestamp: None,
            })
            .collect();

        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&fabricated).await.unwrap();
        assert!(
            !db.is_synced().await.unwrap(),
            "the fixture must exercise the UNAUTHORITATIVE tier"
        );
        let cfg = WalletConfig {
            puzzle_hashes: vec![ph_hex.clone()],
            address_prefix: "txch".into(),
            ..Default::default()
        };
        let be = WalletBackend::new(db, Arc::new(MockFallback::default()), cfg).with_signer(signer);

        // Hop 1: the input reader every spend builder shares.
        assert!(
            be.spendable_coins(None).await.is_err(),
            "spend inputs must not be read from an unauthoritative replica"
        );
        assert!(
            be.coins_from_ids(&["0".repeat(63) + "0"]).await.is_err(),
            "naming a coin id does not make its row any more verified"
        );

        // Hop 2: the RPC a caller actually reaches, end to end.
        let sent = be
            .send_xch(&SendXch {
                address: encode_address(&ph_hex, "txch").unwrap(),
                amount: Amount::Number(1),
                fee: Amount::Number(0),
                memos: vec![],
                clawback: None,
                auto_submit: false,
            })
            .await;
        assert!(
            sent.is_err(),
            "send_xch must refuse rather than spend fabricated inputs"
        );

        // The control: the ONLY thing that changes is the authority flag.
        be.db
            .force_initial_sync_complete_for_test(true)
            .await
            .unwrap();
        let coins = be
            .spendable_coins(None)
            .await
            .expect("an authoritative replica supplies inputs normally");
        assert_eq!(
            coins.len(),
            50,
            "the same rows are selectable once the replica is authoritative - so the refusal \
             above was the tier gate and not an empty table"
        );
    }

    /// **Proves (F3, #2501 third audit):** the CAT/$DIG and singleton readers are gated TOO, on
    /// the ordinary NO-FEE path where the previous round's gate never fired.
    ///
    /// **Why fee 0 is the whole fixture.** `select_cats` did touch
    /// [`WalletBackend::require_authoritative_coins`] — through the XCH coins it selects to pay
    /// the FEE, and only when `fee > 0`. `resolve_offer_cats` passes fee `0` unconditionally and
    /// an ordinary `send_cat` does whenever the caller sets none, so the CAT path reached the
    /// replica ungated in exactly the common case. A fixture with a fee would have gone green
    /// against the unfixed code — it is the "strongest-looking input is the blindest" trap, with
    /// the fee doing the hiding.
    ///
    /// **Why the assertion is on WHICH error, not merely that one occurred.** Both readers can
    /// fail for a second reason on this backend (no lineage source attached), and a test that
    /// accepted any error would pass against code with no gate at all. The refusal is therefore
    /// pinned to the tier message, and the control flips ONLY the authority flag and shows the
    /// SAME calls getting past it to the lineage failure underneath — which is the observable a
    /// guard relocated below the lineage lookup could not produce.
    #[tokio::test]
    async fn the_cat_and_singleton_readers_refuse_an_unauthoritative_replica_at_zero_fee() {
        let pair = BlsPair::new(4);
        let signer = Arc::new(WalletSigner::new(vec![pair.sk], Bytes32::new([0u8; 32])));
        let ph_hex = hex::encode(*signer.puzzle_hashes().iter().next().unwrap());
        let asset = "dd".repeat(32);

        // A funded CAT position at the wallet's OWN hash — the shape the subscription filter
        // cannot catch, because the wallet hands the peer that hash.
        let mut row = coin_at("c0", &ph_hex, 5_000_000);
        row.asset_id = Some(asset.clone());
        row.created_height = Some(5);
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[row]).await.unwrap();
        assert!(
            !db.is_synced().await.unwrap(),
            "the fixture must exercise the UNAUTHORITATIVE tier"
        );
        let cfg = WalletConfig {
            puzzle_hashes: vec![ph_hex.clone()],
            address_prefix: "txch".into(),
            ..Default::default()
        };
        let be = WalletBackend::new(db, Arc::new(MockFallback::default()), cfg).with_signer(signer);

        let tier_error = |e: &Error| e.to_string().contains("not authoritative");

        // Hop 1: the two readers, called directly at fee 0.
        let cats = be.select_cats(&asset, 1_000, 0).await.unwrap_err();
        assert!(
            tier_error(&cats),
            "select_cats must refuse for being unauthoritative, got {cats}"
        );
        let singleton = be.singleton_parent_child("c0").await.unwrap_err();
        assert!(
            tier_error(&singleton),
            "singleton_parent_child must refuse for being unauthoritative, got {singleton}"
        );

        // Hop 2: the RPC a caller actually reaches, with no fee set.
        let sent = be
            .send_cat(&SendCat {
                asset_id: asset.clone(),
                address: encode_address(&ph_hex, "txch").unwrap(),
                amount: Amount::Number(1_000),
                fee: Amount::Number(0),
                include_hint: true,
                memos: vec![],
                clawback: None,
                auto_submit: false,
            })
            .await
            .unwrap_err();
        assert!(
            tier_error(&sent),
            "a fee-0 send_cat must refuse rather than spend from an unauthoritative replica, \
             got {sent}"
        );

        // The control: the ONLY thing that changes is the authority flag. Both calls now get
        // PAST the tier gate and fail on the missing lineage source underneath, which is a
        // different failure — so the refusals above were the gate, not the empty backend.
        be.db
            .force_initial_sync_complete_for_test(true)
            .await
            .unwrap();
        for e in [
            be.select_cats(&asset, 1_000, 0).await.unwrap_err(),
            be.singleton_parent_child("c0").await.unwrap_err(),
        ] {
            assert!(
                !tier_error(&e) && e.to_string().contains("lineage"),
                "past the gate, the next failure is the lineage source, got {e}"
            );
        }
    }

    /// Point-read live sync (§18.12): `refresh_tracked_coins` reads the wallet's coins from the
    /// fallback tier, upserts them into the DB, and marks the DB synced — so coin selection then
    /// runs over live-synced state. Proven with a [`MockFallback`] holding one XCH coin at the
    /// signer's puzzle hash (no chain touched).
    #[tokio::test]
    async fn refresh_tracked_coins_populates_the_db_for_selection() {
        let pair = BlsPair::new(2);
        let signer = Arc::new(WalletSigner::new(vec![pair.sk], Bytes32::new([0u8; 32])));
        let ph = *signer.puzzle_hashes().iter().next().unwrap();
        let ph_hex = hex::encode(ph);
        let db = WalletDb::open_in_memory().await.unwrap();
        let fallback = MockFallback::with_coins(vec![FallbackCoin {
            coin_id: "aa".repeat(32),
            parent_coin_info: "11".repeat(32),
            puzzle_hash: ph_hex.clone(),
            amount: 7_000,
            created_height: Some(5),
            spent_height: None,
            created_timestamp: Some(1),
            spent_timestamp: None,
        }]);
        let cfg = WalletConfig {
            puzzle_hashes: vec![ph_hex.clone()],
            address_prefix: "txch".into(),
            ..Default::default()
        };
        let be = WalletBackend::new(db, Arc::new(fallback), cfg).with_signer(signer);

        // Before the sync the replica is not authoritative, so selecting spend inputs from it
        // is REFUSED — not answered with an empty set, which a caller could not distinguish
        // from a genuinely empty wallet.
        assert!(
            be.spendable_coins(None).await.is_err(),
            "an unsynced replica must refuse to supply spend inputs"
        );
        // Sync from the fallback → the coin lands in the DB.
        let n = be.refresh_tracked_coins().await.unwrap();
        assert_eq!(n, 1, "one XCH coin synced from the fallback");
        // After the sync the coin is selectable over the (now live-synced) DB.
        let coins = be.spendable_coins(None).await.unwrap();
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].amount, 7_000, "the synced coin is selectable");
        assert!(
            be.db.sync_state().await.unwrap().initial_sync_complete,
            "DB marked synced"
        );
    }

    /// **Proves (dig-node#394):** a coin found by HINT never reaches `coins` on the point-read
    /// tier, and never becomes a selectable XCH input — while a coin at the wallet's OWN puzzle
    /// hash still does.
    ///
    /// THE BUG THIS PINS. `refresh_tracked_coins` fetched by puzzle hash AND by hint and upserted
    /// both. A row with no `asset_id` means XCH, and anybody may `CREATE_COIN` with any hint, so
    /// one mojo per displayed base unit bought a fabricated XCH balance from an attacker holding
    /// nothing but the victim's public address. Worse than the wrong figure: selection is
    /// largest-first and nobody can spend the coin, so it is a permanent XCH send kill-switch.
    /// This tier needs no peer at all — the coinset oracle serves it.
    ///
    /// FIXTURE DESIGN — the honest coin is what makes this a PLACEMENT test rather than an
    /// outcome test. "The balance is 999999999 short" is satisfied identically by a correct
    /// re-route and by a refresh that fetched nothing at all, and the second is a different bug.
    /// So an ordinary XCH coin at the wallet's own p2 hash rides along as a truthful control: it
    /// must still be admitted, still be selectable, and still be the ENTIRE balance. And the
    /// fabricated coin is asserted present in STAGING, so "not in `coins`" cannot be satisfied by
    /// dropping it on the floor either — the two assertions together pin where it went, not
    /// merely where it did not go.
    #[tokio::test]
    async fn a_hinted_coin_is_staged_while_a_coin_at_our_own_hash_is_admitted() {
        use super::super::fallback::ChainFallback;

        struct TwoTierFallback {
            at_our_hash: FallbackCoin,
            hinted: FallbackCoin,
        }
        #[async_trait::async_trait]
        impl ChainFallback for TwoTierFallback {
            async fn coin_records_by_puzzle_hashes(
                &self,
                _phs: &[String],
            ) -> Result<Vec<FallbackCoin>> {
                Ok(vec![self.at_our_hash.clone()])
            }
            async fn coin_records_by_hints(&self, _hints: &[String]) -> Result<Vec<FallbackCoin>> {
                Ok(vec![self.hinted.clone()])
            }
            async fn coin_record_by_id(&self, _coin_id: &str) -> Result<Option<FallbackCoin>> {
                Ok(None)
            }
            async fn coin_spend(&self, _coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
                Ok(None)
            }
            async fn coin_records_by_parent(&self, _p: &str) -> Result<Vec<FallbackCoin>> {
                Ok(vec![])
            }
            fn is_live(&self) -> bool {
                true
            }
        }

        let pair = BlsPair::new(3);
        let signer = Arc::new(WalletSigner::new(vec![pair.sk], Bytes32::new([0u8; 32])));
        let ph = *signer.puzzle_hashes().iter().next().unwrap();
        let ph_hex = hex::encode(ph);

        // What the attacker places: a coin at the derived $DIG hash for this victim, hinted to
        // them, for a number they will read as their balance. It costs one mojo per base unit and
        // needs only `ph`, which is public.
        let derived_hash =
            digstore_chain::cat::cat_puzzle_hash(ph, digstore_chain::dig::DIG_ASSET_ID);
        let fallback = TwoTierFallback {
            at_our_hash: FallbackCoin {
                coin_id: "aa".repeat(32),
                parent_coin_info: "11".repeat(32),
                puzzle_hash: ph_hex.clone(),
                amount: 7_000,
                created_height: Some(5),
                spent_height: None,
                created_timestamp: Some(1),
                spent_timestamp: None,
            },
            hinted: FallbackCoin {
                coin_id: "bb".repeat(32),
                parent_coin_info: "22".repeat(32),
                puzzle_hash: hex::encode(derived_hash),
                amount: 999_999_999,
                created_height: Some(6),
                spent_height: None,
                created_timestamp: Some(2),
                spent_timestamp: None,
            },
        };
        let cfg = WalletConfig {
            puzzle_hashes: vec![ph_hex.clone()],
            address_prefix: "txch".into(),
            ..Default::default()
        };
        let be = WalletBackend::new(
            WalletDb::open_in_memory().await.unwrap(),
            Arc::new(fallback),
            cfg,
        )
        .with_signer(signer);

        // No lineage source is attached, so nothing can prove the fabricated coin — which is the
        // attacker's own situation, since no parent spend exists that would.
        let n = be.refresh_tracked_coins().await.unwrap();
        assert_eq!(n, 1, "only the coin at our own puzzle hash is admitted");

        // WHERE THE FABRICATED COIN WENT: staging, awaiting a proof it cannot get.
        assert_eq!(
            be.db.staged_cat_admission_count().await.unwrap(),
            1,
            "the hinted coin must be STAGED -- not admitted, and not silently dropped"
        );

        // WHAT THE MONEY SURFACES SAY. The control's amount, exactly, and nothing else.
        assert_eq!(
            be.db.balance(None).await.unwrap(),
            7_000,
            "the fabricated coin must contribute nothing to the XCH balance"
        );
        let selectable = be.db.unspent_coins(None).await.unwrap();
        assert_eq!(
            selectable.len(),
            1,
            "and must never become a selectable XCH input: selection is largest-first, so one \\
             unspendable coin at the head is a permanent send kill-switch"
        );
        assert_eq!(
            selectable[0].coin_id,
            "aa".repeat(32),
            "the one selectable coin is the honest one"
        );
    }

    /// A locked wallet (no signer ⇒ no tracked puzzle hashes) is a clean no-op refresh — never an
    /// error, never a spurious sync.
    #[tokio::test]
    async fn refresh_tracked_coins_is_a_noop_when_locked() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );
        assert_eq!(be.refresh_tracked_coins().await.unwrap(), 0);
    }

    /// Like [`spend_backend`] but the broadcaster is a [`ConsentBroadcaster`] wrapping the mock —
    /// so a broadcast reaches the (mock) network ONLY after per-op consent is armed (#371).
    async fn consent_spend_backend(
        fund: u64,
    ) -> (
        WalletBackend,
        std::sync::Arc<MockBroadcaster>,
        BroadcastConsent,
    ) {
        let (base, mock, ph) = spend_backend(fund).await;
        let consent = BroadcastConsent::new();
        let gated = Arc::new(ConsentBroadcaster::new(mock.clone(), consent.clone()));
        // Rebuild the backend attaching the consent-gated broadcaster in place of the plain mock.
        let be = base.with_broadcaster(gated);
        let _ = ph;
        (be, mock, consent)
    }

    /// #371 (§18.21): `send_xch` builds + signs + validates, but the node broadcasts on the
    /// paired caller's behalf ONLY with explicit per-op consent. Unconsented → fails closed,
    /// nothing spent; consented → broadcasts exactly once.
    #[tokio::test]
    async fn send_xch_broadcasts_only_with_per_op_consent() {
        let (be, mock, consent) = consent_spend_backend(1_000).await;
        let dest = encode_address(&"22".repeat(32), "txch").unwrap();
        let body = format!(r#"{{"address":"{dest}","amount":600,"fee":10,"auto_submit":true}}"#);

        // Unconsented: the spend builds + signs + validates, but the broadcast is refused —
        // nothing reaches the (mock) network and dispatch returns a non-200 fail-closed status.
        let (status, resp) = be.dispatch("send_xch", &body).await;
        assert_ne!(
            status, 200,
            "unconsented broadcast must fail closed: {resp}"
        );
        assert_eq!(
            mock.sent.lock().unwrap().len(),
            0,
            "nothing is broadcast without per-op consent"
        );

        // Consent armed: the same op now signs + broadcasts exactly once.
        consent.arm();
        let (status, resp) = be.dispatch("send_xch", &body).await;
        assert_eq!(status, 200, "{resp}");
        assert_eq!(
            mock.sent.lock().unwrap().len(),
            1,
            "a consented op broadcasts exactly once"
        );
    }

    #[tokio::test]
    async fn send_xch_dispatch_builds_validates_and_broadcasts() {
        let (be, bc, _ph) = spend_backend(1_000).await;
        let dest = encode_address(&"22".repeat(32), "txch").unwrap();
        let body = format!(r#"{{"address":"{dest}","amount":600,"fee":10,"auto_submit":true}}"#);
        let (status, resp) = be.dispatch("send_xch", &body).await;
        assert_eq!(status, 200, "{resp}");
        let tr: TransactionResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(tr.summary.fee.to_u64(), Some(10));
        assert!(!tr.coin_spends.is_empty());
        assert_eq!(
            bc.sent.lock().unwrap().len(),
            1,
            "auto_submit broadcasts once"
        );
    }

    #[tokio::test]
    async fn spend_without_signer_is_locked_error() {
        // No signer attached → spend building must fail (C.6), not panic.
        let be = backend_with(vec![], true).await;
        let dest = encode_address(&"22".repeat(32), "xch").unwrap();
        let body = format!(r#"{{"address":"{dest}","amount":1,"fee":0}}"#);
        let (status, body) = be.dispatch("send_xch", &body).await;
        assert_eq!(status, 500);
        assert!(body.contains("locked") || body.contains("signing key"));
    }

    #[tokio::test]
    async fn view_and_sign_and_submit_round_trip() {
        let (be, bc, _ph) = spend_backend(1_000).await;
        // Build (no broadcast) to get coin_spends.
        let dest = encode_address(&"33".repeat(32), "txch").unwrap();
        let build_body =
            format!(r#"{{"address":"{dest}","amount":500,"fee":0,"auto_submit":false}}"#);
        let (s, resp) = be.dispatch("send_xch", &build_body).await;
        assert_eq!(s, 200, "{resp}");
        let built: TransactionResponse = serde_json::from_str(&resp).unwrap();
        let cs_json = serde_json::to_string(&built.coin_spends).unwrap();

        // view_coin_spends summarizes the same spends.
        let (s, resp) = be
            .dispatch(
                "view_coin_spends",
                &format!(r#"{{"coin_spends":{cs_json}}}"#),
            )
            .await;
        assert_eq!(s, 200, "{resp}");
        let view: ViewCoinSpendsResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(view.summary.inputs.len(), 1);

        // sign_coin_spends returns a bundle; submit_transaction broadcasts it.
        let (s, resp) = be
            .dispatch(
                "sign_coin_spends",
                &format!(r#"{{"coin_spends":{cs_json},"auto_submit":false}}"#),
            )
            .await;
        assert_eq!(s, 200, "{resp}");
        let signed: SignCoinSpendsResponse = serde_json::from_str(&resp).unwrap();
        let bundle_json = serde_json::to_string(&signed.spend_bundle).unwrap();
        let (s, _resp) = be
            .dispatch(
                "submit_transaction",
                &format!(r#"{{"spend_bundle":{bundle_json}}}"#),
            )
            .await;
        assert_eq!(s, 200);
        assert_eq!(
            bc.sent.lock().unwrap().len(),
            1,
            "submit broadcasts the bundle"
        );
    }

    #[tokio::test]
    async fn offer_and_did_dispatch_end_to_end() {
        // A single wallet backend with a signer + a large funding coin drives the offer +
        // DID dispatch surface: make_offer stores an offer, get_offers/get_offer/view_offer
        // read it, cancel_offer flips its status, create_did builds a valid DID spend. No
        // broadcast reaches the network (MockBroadcaster).
        let (be, _bc, ph) = spend_backend(1_000_000).await;
        let addr = encode_address(&hex::encode(ph), "txch").unwrap();

        // make_offer: OFFER 300 XCH, REQUEST 500 XCH to our own address (auto_import).
        let body = format!(
            r#"{{"offered_assets":[{{"asset_id":null,"amount":300}}],"requested_assets":[{{"asset_id":null,"amount":500}}],"fee":0,"receive_address":"{addr}"}}"#
        );
        let (s, resp) = be.dispatch("make_offer", &body).await;
        assert_eq!(s, 200, "{resp}");
        let mo: MakeOfferResponse = serde_json::from_str(&resp).unwrap();
        assert!(mo.offer.starts_with("offer1"), "got {}", mo.offer);
        assert_eq!(mo.offer_id.len(), 64);

        // get_offers returns the stored offer (auto_import defaulted true).
        let (s, resp) = be.dispatch("get_offers", "{}").await;
        assert_eq!(s, 200);
        let go: GetOffersResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(go.offers.len(), 1);
        assert_eq!(go.offers[0].offer_id, mo.offer_id);
        assert!(matches!(go.offers[0].status, OfferRecordStatus::Active));

        // view_offer summarizes it: maker gives 300, taker pays 500.
        let vo_body = format!(
            r#"{{"offer":{}}}"#,
            serde_json::to_string(&mo.offer).unwrap()
        );
        let (s, resp) = be.dispatch("view_offer", &vo_body).await;
        assert_eq!(s, 200, "{resp}");
        let vo: ViewOfferResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(vo.offer.maker[0].amount.to_u64(), Some(300));
        assert_eq!(vo.offer.taker[0].amount.to_u64(), Some(500));

        // create_did builds + validates a DID creation (no broadcast: auto_submit default false).
        let (s, resp) = be.dispatch("create_did", r#"{"name":"me","fee":0}"#).await;
        assert_eq!(s, 200, "{resp}");
        let tr: TransactionResponse = serde_json::from_str(&resp).unwrap();
        assert!(!tr.coin_spends.is_empty());

        // cancel_offer flips the stored offer to cancelled.
        let (s, resp) = be
            .dispatch(
                "cancel_offer",
                &format!(r#"{{"offer_id":"{}","fee":0}}"#, mo.offer_id),
            )
            .await;
        assert_eq!(s, 200, "{resp}");
        let (_s, resp) = be
            .dispatch("get_offer", &format!(r#"{{"offer_id":"{}"}}"#, mo.offer_id))
            .await;
        let one: GetOfferResponse = serde_json::from_str(&resp).unwrap();
        assert!(matches!(one.offer.status, OfferRecordStatus::Cancelled));
    }

    #[tokio::test]
    async fn transfer_without_signer_is_locked_and_combine_needs_two() {
        // Secret-custody gate (C.6): a spend method with no signer attached fails locked.
        let be = backend_with(vec![], true).await;
        let (status, body) = be
            .dispatch(
                "transfer_nfts",
                r#"{"nft_ids":["aa"],"address":"xch1x","fee":0}"#,
            )
            .await;
        assert_eq!(status, 500);
        assert!(body.contains("locked") || body.contains("signing key"));

        // combine_offers needs at least two offers → 400.
        let (status, _b) = be
            .dispatch("combine_offers", r#"{"offers":["offer1abc"]}"#)
            .await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn get_nfts_and_get_dids_return_reconstructed_rows() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let nft = NftRecord {
            launcher_id: "aa".repeat(32),
            collection_id: None,
            collection_name: None,
            minter_did: None,
            owner_did: None,
            visible: true,
            sensitive_content: false,
            name: Some("Test".into()),
            created_height: Some(5),
            coin_id: "bb".repeat(32),
            address: "xch1".into(),
            royalty_address: "xch1".into(),
            royalty_ten_thousandths: 300,
            data_uris: vec!["u".into()],
            data_hash: None,
            metadata_uris: vec![],
            metadata_hash: None,
            license_uris: vec![],
            license_hash: None,
            edition_number: Some(1),
            edition_total: Some(1),
            icon_url: None,
            created_timestamp: None,
            special_use_type: None,
        };
        db.upsert_nft(&NftDbRow {
            launcher_id: nft.launcher_id.clone(),
            coin_id: nft.coin_id.clone(),
            collection_id: None,
            minter_did: None,
            owner_did: None,
            name: nft.name.clone(),
            visible: true,
            created_height: Some(5),
            record_json: serde_json::to_string(&nft).unwrap(),
        })
        .await
        .unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );

        let (s, resp) = be
            .dispatch(
                "get_nfts",
                r#"{"offset":0,"limit":10,"sort_mode":"name","include_hidden":false}"#,
            )
            .await;
        assert_eq!(s, 200, "{resp}");
        let got: GetNftsResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(got.total, 1);
        assert_eq!(got.nfts[0].launcher_id, nft.launcher_id);

        // get_nft by hex launcher id.
        let (_s, resp) = be
            .dispatch("get_nft", &format!(r#"{{"nft_id":"{}"}}"#, nft.launcher_id))
            .await;
        let one: GetNftResponse = serde_json::from_str(&resp).unwrap();
        assert!(one.nft.is_some());
    }

    // ---- #205 PR4 dispatch coverage: options/actions/themes/network -----------

    /// A backend funded with TWO separate spendable coins (mint_option needs one to lock the
    /// underlying and a distinct one to fund the launcher — realistic for any multi-UTXO
    /// wallet).
    async fn two_coin_spend_backend(a: u64, b: u64) -> WalletBackend {
        let pair = BlsPair::new(2);
        let signer = Arc::new(WalletSigner::new(vec![pair.sk], Bytes32::new([0u8; 32])));
        let ph = *signer.puzzle_hashes().iter().next().unwrap();
        let db = WalletDb::open_in_memory().await.unwrap();
        for (i, amount) in [a, b].into_iter().enumerate() {
            db.upsert_coin(&CoinRow {
                coin_id: format!("coin{i}"),
                parent_coin_info: "33".repeat(32),
                puzzle_hash: hex::encode(ph),
                amount: amount.to_string(),
                created_height: Some(1),
                spent_height: None,
                asset_id: None,
                hint: None,
                created_timestamp: None,
                spent_timestamp: None,
            })
            .await
            .unwrap();
        }
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let cfg = WalletConfig {
            puzzle_hashes: vec![hex::encode(ph)],
            address_prefix: "txch".into(),
            ..Default::default()
        };
        WalletBackend::new(db, Arc::new(MockFallback::default()), cfg).with_signer(signer)
    }

    #[tokio::test]
    async fn mint_option_dispatch_builds_transfers_and_lists() {
        let be = two_coin_spend_backend(2_000, 100).await;

        // Mint an XCH-underlying, XCH-strike option (no broadcast: auto_submit false).
        let body = r#"{"expiration_seconds":3600,"underlying":{"amount":1000},"strike":{"amount":500},"fee":0}"#;
        let (s, resp) = be.dispatch("mint_option", body).await;
        assert_eq!(s, 200, "{resp}");
        let minted: MintOptionResponse = serde_json::from_str(&resp).unwrap();
        assert!(!minted.coin_spends.is_empty());

        // A CAT-underlying mint is explicitly out of scope → a clear 400, not a panic.
        let cat_body = format!(
            r#"{{"expiration_seconds":10,"underlying":{{"asset_id":"{}","amount":1}},"strike":{{"amount":1}},"fee":0}}"#,
            "aa".repeat(32)
        );
        let (s, resp) = be.dispatch("mint_option", &cat_body).await;
        assert_eq!(s, 400, "{resp}");
        assert!(resp.contains("XCH underlying"));

        // exercise_options is a documented follow-on: a clear 500, never a panic.
        let (s, resp) = be
            .dispatch("exercise_options", r#"{"option_ids":["aa"],"fee":0}"#)
            .await;
        assert_eq!(s, 500, "{resp}");
        assert!(resp.contains("not yet implemented"));
    }

    #[tokio::test]
    async fn actions_themes_and_network_dispatch_round_trip() {
        let be = backend_with(vec![], true).await;

        // resync_cat / update_cat.
        let (s, _) = be.dispatch("resync_cat", r#"{"asset_id":"a1"}"#).await;
        assert_eq!(s, 200);
        let update_cat_body = r#"{"record":{"asset_id":"a1","name":"N","ticker":"T","precision":3,"description":null,"icon_url":null,"visible":true,"balance":0,"selectable_balance":0,"revocation_address":null}}"#;
        let (s, resp) = be.dispatch("update_cat", update_cat_body).await;
        assert_eq!(s, 200, "{resp}");

        // increase_derivation_index then get_sync_status reflects the floor.
        let (s, _) = be
            .dispatch(
                "increase_derivation_index",
                r#"{"unhardened":true,"index":25}"#,
            )
            .await;
        assert_eq!(s, 200);
        let (_s, resp) = be.dispatch("get_sync_status", "{}").await;
        let status: GetSyncStatusResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(status.unhardened_derivation_index, 25);

        // increase_derivation_index with neither tree selected is a clear 400.
        let (s, _) = be
            .dispatch("increase_derivation_index", r#"{"index":5}"#)
            .await;
        assert_eq!(s, 400);

        // themes round trip (Sage's real request is `{nft_id}` only — see `sage::themes`).
        let (s, _) = be.dispatch("save_user_theme", r#"{"nft_id":"n1"}"#).await;
        assert_eq!(s, 200);
        let (s, resp) = be.dispatch("get_user_theme", r#"{"nft_id":"n1"}"#).await;
        assert_eq!(s, 200);
        let theme: GetUserThemeResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            theme.theme.as_deref(),
            Some(crate::sage::themes::DERIVED_THEME_PLACEHOLDER)
        );
        let (s, resp) = be.dispatch("get_user_themes", "{}").await;
        assert_eq!(s, 200);
        let themes: GetUserThemesResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(themes.themes, vec!["n1"]);
        let (s, _) = be.dispatch("delete_user_theme", r#"{"nft_id":"n1"}"#).await;
        assert_eq!(s, 200);

        // peers round trip.
        let (s, _) = be.dispatch("add_peer", r#"{"ip":"1.2.3.4"}"#).await;
        assert_eq!(s, 200);
        let (s, resp) = be.dispatch("get_peers", "{}").await;
        assert_eq!(s, 200);
        let peers: GetPeersResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(peers.peers.len(), 1);
        assert_eq!(peers.peers[0].ip_addr, "1.2.3.4");
        let (s, _) = be.dispatch("remove_peer", r#"{"ip":"1.2.3.4"}"#).await;
        assert_eq!(s, 200);

        // network settings + get_networks/get_network.
        let (s, resp) = be.dispatch("get_networks", "{}").await;
        assert_eq!(s, 200, "{resp}");
        let list: NetworkList = serde_json::from_str(&resp).unwrap();
        assert!(list.networks.contains_key("mainnet"));

        let (s, resp) = be.dispatch("get_network", "{}").await;
        assert_eq!(s, 200);
        let net: GetNetworkResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(net.network.name, "mainnet");

        let (s, _) = be.dispatch("set_network", r#"{"name":"testnet11"}"#).await;
        assert_eq!(s, 200);
        let (_s, resp) = be.dispatch("get_network", "{}").await;
        let net: GetNetworkResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(net.network.name, "testnet11");

        let (s, _) = be
            .dispatch("set_discover_peers", r#"{"discover_peers":false}"#)
            .await;
        assert_eq!(s, 200);
        let (s, _) = be
            .dispatch("set_target_peers", r#"{"target_peers":5}"#)
            .await;
        assert_eq!(s, 200);
        let (s, _) = be
            .dispatch("set_delta_sync", r#"{"delta_sync":false}"#)
            .await;
        assert_eq!(s, 200);
        let (s, _) = be
            .dispatch(
                "set_change_address",
                r#"{"fingerprint":1,"change_address":"xch1abc"}"#,
            )
            .await;
        assert_eq!(s, 200);
    }

    /// **Proves:** [`WalletBackend::events`] is always populated, and
    /// [`WalletBackend::with_events`] lets a shared bus be attached — the `GET /events`
    /// SSE handler (`sage::transport`) always has somewhere to subscribe, and a
    /// caller-attached bus (e.g. shared with the sync loop) is honored.
    #[tokio::test]
    async fn event_bus_is_always_present_and_can_be_shared() {
        let be = backend_with(vec![], true).await;
        assert_eq!(be.events().subscriber_count(), 0);

        let shared = std::sync::Arc::new(super::super::events::EventBus::with_capacity(4));
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be2 = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        )
        .with_events(shared.clone());
        let mut rx = be2.events().subscribe();
        shared.publish(super::super::events::SyncEvent::Stop);
        assert_eq!(
            rx.recv().await.unwrap(),
            super::super::events::SyncEvent::Stop
        );
    }

    // ---- #407: identity-scoped reads + honest sync + CAT attribution -----

    /// A `CoinRow` at `puzzle_hash` (XCH unless `asset_id`/`hint` given).
    fn coin_at(id: &str, ph: &str, amount: u64) -> CoinRow {
        CoinRow {
            coin_id: id.into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: ph.into(),
            amount: amount.to_string(),
            created_height: Some(10),
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    /// **Regression (#407 / #399): honest sync state.** An empty or not-yet-caught-up DB
    /// MUST read as NOT synced (the client derives `synced` as `synced_coins >= total_coins`
    /// with `total_coins == 0` treated as synced) so it never adopts a silent synced-zero.
    #[tokio::test]
    async fn get_sync_status_reports_not_synced_on_empty_or_unsynced_db() {
        // Fresh DB: initial catch-up NOT complete, no wallet tracked.
        let db = WalletDb::open_in_memory().await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );
        let (status, body) = be.dispatch("get_sync_status", "{}").await;
        assert_eq!(status, 200);
        let r: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert!(
            r.total_coins > r.synced_coins,
            "empty/unsynced DB must read NOT synced (got synced={} total={})",
            r.synced_coins,
            r.total_coins
        );
        assert_eq!(r.selectable_balance.to_u64(), Some(0));

        // Even with the DB marked caught up, a wallet the node is NOT tracking (no login,
        // no config) still reads NOT synced — never a silent synced-0.
        let db2 = WalletDb::open_in_memory().await.unwrap();
        db2.force_initial_sync_complete_for_test(true)
            .await
            .unwrap();
        let be2 = WalletBackend::new(
            db2,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );
        let (_s, body) = be2.dispatch("get_sync_status", "{}").await;
        let r: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert!(
            r.total_coins > r.synced_coins,
            "untracked wallet must read NOT synced"
        );
        assert_eq!(r.selectable_balance.to_u64(), Some(0));
    }

    /// **Regression (#407): identity-scoped reads.** `login` with the client's PUBLIC
    /// puzzle hashes scopes reads to the CLIENT's coins; an identity the node isn't tracking
    /// reads as the explicit not-tracking state (NEVER a silent 0), and a coin belonging to
    /// a different wallet in the same DB is never counted for the client.
    #[tokio::test]
    async fn identity_scoped_reads_return_client_balance_never_other_wallets() {
        let client_ph = "aa".repeat(32);
        let other_ph = "bb".repeat(32);
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[
            coin_at("client1", &client_ph, 7_000),
            coin_at("other1", &other_ph, 9_999),
        ])
        .await
        .unwrap();
        // The catch-up covered BOTH wallets' addresses, so the scoping assertions below measure
        // scoping and not coverage (dig_ecosystem#2878).
        db.record_coverage(&CoveredSet::from_hex([
            client_ph.as_str(),
            other_ph.as_str(),
        ]))
        .await
        .unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        // Identity comes ONLY from the client's login — the node has no own wallet config.
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );

        // No login → not tracking → NOT synced + balance 0 (never the other wallet's coin).
        let (_s, body) = be.dispatch("get_sync_status", "{}").await;
        let r: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(r.selectable_balance.to_u64(), Some(0));
        assert!(r.total_coins > r.synced_coins, "untracked reads NOT synced");

        // Login with the client's public puzzle hash → scope to the client's coin only.
        let (s, _) = be
            .dispatch(
                "login",
                &format!(r#"{{"fingerprint":42,"puzzle_hashes":["{client_ph}"]}}"#),
            )
            .await;
        assert_eq!(s, 200);
        let (_s, body) = be.dispatch("get_sync_status", "{}").await;
        let r: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(
            r.selectable_balance.to_u64(),
            Some(7_000),
            "must report the CLIENT's balance, not the other wallet's 9999"
        );
        assert_eq!(
            r.synced_coins, r.total_coins,
            "tracked + caught up = synced"
        );
        assert!(r.total_coins >= 1);

        // logout → not tracking again.
        be.dispatch("logout", "{}").await;
        let (_s, body) = be.dispatch("get_sync_status", "{}").await;
        let r: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert!(
            r.total_coins > r.synced_coins,
            "after logout reads NOT synced"
        );
        assert_eq!(r.selectable_balance.to_u64(), Some(0));
    }

    /// `login` accepts bech32m ADDRESSES too, decoding them to puzzle hashes for scoping.
    #[tokio::test]
    async fn login_accepts_addresses_for_scoping() {
        let ph = "aa".repeat(32);
        let addr = encode_address(&ph, "xch").unwrap();
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[coin_at("c1", &ph, 4_200)]).await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );
        be.dispatch(
            "login",
            &format!(r#"{{"fingerprint":1,"addresses":["{addr}"]}}"#),
        )
        .await;
        let (_s, body) = be.dispatch("get_sync_status", "{}").await;
        let r: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(r.selectable_balance.to_u64(), Some(4_200));
    }

    /// **Regression (#407): CAT `asset_id` attribution.** After a CAT coin is synced (stored
    /// with `asset_id: None`) and attributed by uncurrying its parent spend, `get_cats`
    /// returns the real TAIL/asset id for the connected identity — so `$DIG` resolves.
    #[tokio::test]
    async fn get_cats_returns_cat_tail_after_synced_cat_coin() {
        use super::super::singleton::{reconstruct_coins, LineageSource, ParentSpend};
        use chia_sdk_test::Simulator;
        use chia_traits::Streamable;
        use chia_wallet_sdk::driver::{
            Cat as SdkCat, CatSpend, SpendContext, SpendWithConditions, StandardLayer,
        };
        use chia_wallet_sdk::types::Conditions;

        // A LineageSource returning one prebuilt parent spend (the CAT parent).
        struct OneParent {
            parent_id: String,
            spend: ParentSpend,
        }
        #[async_trait::async_trait]
        impl LineageSource for OneParent {
            async fn parent_spend(
                &self,
                parent_coin_id: &str,
                _spent_height: u32,
            ) -> Result<singleton::LineageAnswer> {
                // A parent this double does not hold is one the node could not READ, which is
                // what the production source reports for an unresolvable parent.
                Ok(singleton::LineageAnswer::from_lookup(
                    (parent_coin_id == self.parent_id).then(|| self.spend.clone()),
                    singleton::LineageAnswer::Unavailable,
                ))
            }
        }

        // Issue a real CAT on the simulator, then spend it to produce a child CAT coin
        // (its parent is a CAT coin — what `Cat::parse_children` uncurries the tail from).
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1_000);
        let alice_p2 = StandardLayer::new(alice.pk);
        let memos = ctx.hint(alice.puzzle_hash).unwrap();
        let (issue_cat, cats) = SdkCat::single_issuance(
            ctx,
            alice.coin.coin_id(),
            // See the `single_issuance` note above: `None` keeps the eve coin's puzzle hash, and
            // so this fixture's CAT, byte-identical to the 0.30 `issue_with_coin` it replaces.
            None,
            1_000,
            Conditions::new().create_coin(alice.puzzle_hash, 1_000, memos),
        )
        .unwrap();
        alice_p2.spend(ctx, alice.coin, issue_cat).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();
        let cat0 = cats[0];
        let inner = alice_p2
            .spend_with_conditions(
                ctx,
                Conditions::new().create_coin(alice.puzzle_hash, 1_000, memos),
            )
            .unwrap();
        SdkCat::spend_all(ctx, &[CatSpend::new(cat0, inner)]).unwrap();
        sim.spend_coins(ctx.take(), &[alice.sk]).unwrap();
        let child_cat = cat0.child(alice.puzzle_hash, 1_000);

        // The wallet synced the child CAT coin — persisted with asset_id None.
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut row = coin_at(
            &hex::encode(child_cat.coin.coin_id()),
            &hex::encode(child_cat.coin.puzzle_hash),
            child_cat.coin.amount,
        );
        row.parent_coin_info = hex::encode(child_cat.coin.parent_coin_info);
        db.upsert_coin(&row).await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();

        // Attribute CATs by uncurrying the parent spend (the sync attribution step).
        let parent = ParentSpend {
            coin: cat0.coin,
            puzzle_reveal: sim
                .puzzle_reveal(cat0.coin.coin_id())
                .unwrap()
                .to_bytes()
                .unwrap(),
            solution: sim
                .solution(cat0.coin.coin_id())
                .unwrap()
                .to_bytes()
                .unwrap(),
        };
        let lineage = OneParent {
            parent_id: hex::encode(child_cat.coin.parent_coin_info),
            spend: parent,
        };
        let stats = reconstruct_coins(
            &db,
            &lineage,
            "xch",
            &HashSet::new(),
            &db.all_coins().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(stats.cats, 1, "the synced CAT coin was attributed");

        // Login as the CAT owner → get_cats returns the real tail + scoped balance.
        let owner_ph = hex::encode(alice.puzzle_hash);
        // Record the catch-up this fixture implies. It writes the replica directly and predates
        // the coverage model, so it described a node holding the owner's coins while claiming to
        // follow no address at all — a state no real sync produces, and one `get_cats` must now
        // refuse rather than answer (dig-node#247).
        db.record_coverage(&CoveredSet::from_hex([owner_ph.as_str()]))
            .await
            .unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );
        be.dispatch(
            "login",
            &format!(r#"{{"fingerprint":1,"puzzle_hashes":["{owner_ph}"]}}"#),
        )
        .await;
        let (status, body) = be.dispatch("get_cats", "{}").await;
        assert_eq!(status, 200);
        let resp: GetCatsResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.cats.len(), 1, "the owned CAT is listed");
        assert_eq!(
            resp.cats[0].asset_id.as_deref(),
            Some(hex::encode(cat0.info.asset_id).as_str()),
            "get_cats returns the uncurried TAIL"
        );
        assert_eq!(resp.cats[0].balance.to_u64(), Some(1_000));
    }

    /// **#430 — the wallet coin-DB sync feeds $DIG coin selection end-to-end.** The live tip /
    /// send path selects $DIG from the local DB (`select_cats` → `unspent_coins`); nothing
    /// selects until [`WalletBackend::refresh_tracked_coins`] populates the DB from chain. This
    /// drives the FULL path on the `chia-sdk-test` simulator with NO live broadcast: issue a real
    /// CAT hinted to the wallet, expose it through a chain-fallback (`coin_records_by_hints`) + a
    /// lineage source, then prove that BEFORE the sync `select_cats` reports the exact live-funds
    /// failure ("insufficient CAT balance: have 0"), and AFTER `refresh_tracked_coins` the coin
    /// lands in the DB attributed to its TAIL, `select_cats` resolves it, and a CAT send builds +
    /// validates (dig-clvm) + signs + is handed to a recording [`MockBroadcaster`]. This is the
    /// identical mechanism `build_and_broadcast_dig_tip` uses (it just fixes the asset id to
    /// `DIG_ASSET_ID`, which the simulator cannot mint — an arbitrary sim CAT stands in for $DIG).
    #[tokio::test]
    async fn refresh_tracked_coins_feeds_cat_selection_and_build_sign() {
        use super::super::fallback::ChainFallback;
        use super::super::singleton::{LineageSource, ParentSpend};
        use super::super::spend::{self, MockBroadcaster, WalletSigner};
        use chia_sdk_test::Simulator;
        use chia_traits::Streamable;
        use chia_wallet_sdk::driver::{
            Cat as SdkCat, CatSpend, SpendContext, SpendWithConditions, StandardLayer,
        };
        use chia_wallet_sdk::types::Conditions;

        // A chain fallback that returns one CAT coin when queried by the owner's p2 hint —
        // exactly what the live coinset/peer tier does for a $DIG coin hinted to the wallet.
        struct HintFallback {
            owner_ph: String,
            coin: FallbackCoin,
        }
        #[async_trait::async_trait]
        impl ChainFallback for HintFallback {
            async fn coin_records_by_puzzle_hashes(
                &self,
                _phs: &[String],
            ) -> Result<Vec<FallbackCoin>> {
                Ok(vec![]) // the CAT is HINTED to us, not sitting AT our p2 hash
            }
            async fn coin_records_by_hints(&self, hints: &[String]) -> Result<Vec<FallbackCoin>> {
                Ok(if hints.iter().any(|h| h == &self.owner_ph) {
                    vec![self.coin.clone()]
                } else {
                    vec![]
                })
            }
            async fn coin_record_by_id(&self, _coin_id: &str) -> Result<Option<FallbackCoin>> {
                Ok(None)
            }
            async fn coin_spend(&self, _coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
                Ok(None)
            }
            async fn coin_records_by_parent(&self, _parent: &str) -> Result<Vec<FallbackCoin>> {
                Ok(vec![])
            }
            // Stands in for the live coinset/peer tier (#1851: the trait default is fail-closed).
            fn is_live(&self) -> bool {
                true
            }
        }

        // A lineage source returning the CAT's parent spend (so attribution + input resolution work).
        struct OneParent {
            parent_id: String,
            spend: ParentSpend,
        }
        #[async_trait::async_trait]
        impl LineageSource for OneParent {
            async fn parent_spend(
                &self,
                parent_coin_id: &str,
                _spent_height: u32,
            ) -> Result<singleton::LineageAnswer> {
                // A parent this double does not hold is one the node could not READ, which is
                // what the production source reports for an unresolvable parent.
                Ok(singleton::LineageAnswer::from_lookup(
                    (parent_coin_id == self.parent_id).then(|| self.spend.clone()),
                    singleton::LineageAnswer::Unavailable,
                ))
            }
        }

        // Issue a CAT on the simulator, then spend it to a child CAT hinted to alice — the coin a
        // syncing wallet observes on chain.
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let alice = sim.bls(1_000);
        let alice_p2 = StandardLayer::new(alice.pk);
        let memos = ctx.hint(alice.puzzle_hash).unwrap();
        let (issue_cat, cats) = SdkCat::single_issuance(
            ctx,
            alice.coin.coin_id(),
            // See the `single_issuance` note above: `None` keeps the eve coin's puzzle hash, and
            // so this fixture's CAT, byte-identical to the 0.30 `issue_with_coin` it replaces.
            None,
            1_000,
            Conditions::new().create_coin(alice.puzzle_hash, 1_000, memos),
        )
        .unwrap();
        alice_p2.spend(ctx, alice.coin, issue_cat).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();
        let cat0 = cats[0];
        let inner = alice_p2
            .spend_with_conditions(
                ctx,
                Conditions::new().create_coin(alice.puzzle_hash, 1_000, memos),
            )
            .unwrap();
        SdkCat::spend_all(ctx, &[CatSpend::new(cat0, inner)]).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();
        let child_cat = cat0.child(alice.puzzle_hash, 1_000);
        let asset_hex = hex::encode(cat0.info.asset_id);

        // The chain-facing doubles: the child CAT surfaced by hint, and its parent spend.
        let fallback = HintFallback {
            owner_ph: hex::encode(alice.puzzle_hash),
            coin: FallbackCoin {
                coin_id: hex::encode(child_cat.coin.coin_id()),
                parent_coin_info: hex::encode(child_cat.coin.parent_coin_info),
                puzzle_hash: hex::encode(child_cat.coin.puzzle_hash),
                amount: 1_000,
                created_height: Some(5),
                spent_height: None,
                created_timestamp: Some(1),
                spent_timestamp: None,
            },
        };
        let lineage = OneParent {
            parent_id: hex::encode(child_cat.coin.parent_coin_info),
            spend: ParentSpend {
                coin: cat0.coin,
                puzzle_reveal: sim
                    .puzzle_reveal(cat0.coin.coin_id())
                    .unwrap()
                    .to_bytes()
                    .unwrap(),
                solution: sim
                    .solution(cat0.coin.coin_id())
                    .unwrap()
                    .to_bytes()
                    .unwrap(),
            },
        };

        let signer = Arc::new(WalletSigner::new(vec![alice.sk], Bytes32::new([0u8; 32])));
        let db = WalletDb::open_in_memory().await.unwrap();
        let mock = Arc::new(MockBroadcaster::default());
        let cfg = WalletConfig {
            puzzle_hashes: vec![hex::encode(alice.puzzle_hash)],
            address_prefix: "txch".into(),
            ..Default::default()
        };
        let be = WalletBackend::new(db, Arc::new(fallback), cfg)
            .with_signer(signer.clone())
            .with_lineage(Arc::new(lineage))
            .with_broadcaster(mock.clone());

        // BEFORE the sync: selection is REFUSED for the tier, ahead of counting anything.
        //
        // This assertion used to read "insufficient CAT balance: have 0", and that it did is
        // itself the F3 finding: with both spend gates deleted this test stayed green, because
        // the CAT path never reached a gate either way. "Have 0" is also the wrong answer to
        // give — an unauthoritative replica does not know the balance is zero, and a caller
        // cannot distinguish that sentence from a genuinely empty wallet.
        let err = be.select_cats(&asset_hex, 1_000, 0).await.unwrap_err();
        assert!(
            err.to_string().contains("not authoritative"),
            "pre-sync selection is refused for the tier, not answered with a count, got: {err}"
        );

        // The wallet coin-DB sync: read the wallet's own coins from chain + attribute the CAT.
        //
        // The return value counts rows written DIRECTLY into `coins`, and a hinted coin is no
        // longer one of them (dig-node#394): a hint is attacker-controlled, so it is staged and
        // admitted only once its parent spend proves what it is. Zero here is the whole re-route,
        // and the assertions below are what prove the re-route costs no capability — the same
        // coin, the same TAIL, the same selectability, reached through a proof instead of trust.
        let n = be.refresh_tracked_coins().await.unwrap();
        assert_eq!(
            n, 0,
            "a coin found by HINT is staged, never upserted straight into `coins`"
        );
        assert_eq!(
            be.db.staged_cat_admission_count().await.unwrap(),
            0,
            "and the staging table is empty afterwards because the coin was PROMOTED out of it, \
             not because it was never staged -- the next assertion is what tells those apart"
        );

        // AFTER the sync: the coin is in the DB, attributed to its TAIL, and selectable.
        let unspent = be.db.unspent_coins(Some(&asset_hex)).await.unwrap();
        assert_eq!(
            unspent.len(),
            1,
            "the $DIG-standin CAT is now in the coin DB"
        );
        assert_eq!(unspent[0].asset_id.as_deref(), Some(asset_hex.as_str()));

        let (selected, xch_fee) = be
            .select_cats(&asset_hex, 1_000, 0)
            .await
            .expect("select_cats resolves the synced CAT");
        assert_eq!(selected.len(), 1, "one CAT input covers the amount");
        assert!(xch_fee.is_empty(), "no XCH fee coins needed at fee=0");

        // Build + validate (dig-clvm) + sign the CAT send, then hand it to the recording
        // broadcaster — the identical build/sign/broadcast steps the tip runs, NO live send.
        let recipient = Bytes32::new([9u8; 32]);
        let coin_spends = spend::build_cat_send(
            signer.as_ref(),
            &selected,
            recipient,
            1_000,
            alice.puzzle_hash,
            true,
            0,
            &xch_fee,
        )
        .expect("CAT send builds over the synced coin");
        spend::run_and_validate(&coin_spends).expect("dig-clvm validation passes");
        let sig = signer.sign(&coin_spends).unwrap();
        let bundle = SpendBundle::new(coin_spends, sig);
        mock.broadcast(&bundle).await.unwrap();
        assert_eq!(
            mock.sent.lock().unwrap().len(),
            1,
            "the signed tip/send bundle reached the (mock) broadcaster"
        );
    }

    use super::super::events::SyncLifecycle;

    /// **Proves (#369 sync-status):** the sync-status snapshot derives the tri-state from the DB —
    /// `syncing` before the initial catch-up completes, `synced` (with the peak height) after.
    #[tokio::test]
    async fn sync_status_reports_tristate_from_db() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.force_initial_sync_complete_for_test(false)
            .await
            .unwrap();
        let be = WalletBackend::new(
            db.clone(),
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );
        let s = be.sync_status().await.unwrap();
        assert_eq!(s.state, SyncLifecycle::Syncing);

        db.set_peak(123, "aa").await.unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let s = be.sync_status().await.unwrap();
        assert_eq!(s.state, SyncLifecycle::Synced);
        assert_eq!(s.peak_height, Some(123));
    }

    // ---- dig_ecosystem#2878: identity-scoped reads must not answer from an uncovered scope ----

    /// A client identity the completed catch-up never covered, that GENUINELY HOLDS FUNDS on chain.
    ///
    /// FIXTURE DESIGN — this is the only shape that can see the defect, and it needs THREE
    /// properties at once:
    ///
    /// 1. **The catch-up completed**, so `db.is_synced()` is `true`. Without it the pre-fix code
    ///    already reports not-synced and the fixture proves nothing.
    /// 2. **The recorded coverage names a DIFFERENT address** (`covered_ph`) that the replica
    ///    really did sync. A fixture recording NO coverage would also be caught by an
    ///    implementation that merely demanded *some* coverage exist, so the honest control is what
    ///    forces the containment question to be asked about the CLIENT's scope.
    /// 3. **The money is on the CHAIN, not in the replica.** The replica's coin table is empty for
    ///    the client, which is exactly the uncovered state — the DB was never asked to follow that
    ///    address. An unfunded fixture cannot tell "zero because unscoped" from "zero because
    ///    empty", which is the whole defect.
    ///
    /// It also distinguishes the fix's PLACEMENT. Routing these reads through
    /// [`WalletBackend::replica_is_authoritative`] — the address-scoped predicate — would pass a
    /// weaker fixture: with no custody and no watchlist the followed set is EMPTY, every recording
    /// covers it, and the uncovered client scope would still be served a synced zero. Only asking
    /// containment against `scoped_identity()` answers this fixture correctly.
    async fn uncovered_but_funded_client(client_ph: &str) -> (WalletBackend, Arc<MockFallback>) {
        let covered_ph = "bb".repeat(32);
        let db = WalletDb::open_in_memory().await.unwrap();
        // A real, completed catch-up — over an address that is NOT the client's.
        db.record_coverage(&CoveredSet::from_hex([covered_ph.as_str()]))
            .await
            .unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        db.set_peak(REPLICA_PEAK, &"cc".repeat(32)).await.unwrap();
        assert!(
            db.is_synced().await.unwrap(),
            "the fixture must satisfy the bare sync flag, or it cannot see the defect"
        );
        let fb = Arc::new(MockFallback::with_coins(vec![fallback_coin(
            "onchain1",
            client_ph,
            1_599_000_000_000,
            Some(REPLICA_PEAK),
            None,
        )]));
        let be = WalletBackend::new(db, fb.clone(), WalletConfig::default());
        let addr = encode_address(client_ph, "xch").unwrap();
        be.dispatch(
            "login",
            &format!(r#"{{"fingerprint":1,"addresses":["{addr}"]}}"#),
        )
        .await;
        (be, fb)
    }

    /// **Regression (dig_ecosystem#2878): `get_sync_status` must not report a complete, synced,
    /// zero view for a scope the catch-up never covered.**
    ///
    /// Before the fix a client holding 1.599 XCH was answered `selectable_balance: 0` with
    /// `synced_coins == total_coins == 0`, which every client renders as *"synced, balance 0"*.
    #[tokio::test]
    async fn an_uncovered_client_scope_is_never_reported_as_a_synced_zero() {
        let client_ph = "aa".repeat(32);
        let (be, _fb) = uncovered_but_funded_client(&client_ph).await;

        let (_s, body) = be.dispatch("get_sync_status", "{}").await;
        let r: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert!(
            r.total_coins > r.synced_coins,
            "an uncovered scope was reported fully synced (synced={} total={}); the replica was \
             never asked to follow this client's addresses, so it cannot say the view is complete",
            r.synced_coins,
            r.total_coins
        );
    }

    /// **Regression (dig_ecosystem#2878): the coin read falls to the chain for an uncovered scope.**
    ///
    /// The companion to the status assertion above, and the one that shows the user's money. An
    /// empty list from the replica reads downstream as *"a chain was consulted and this wallet is
    /// empty"*.
    #[tokio::test]
    async fn an_uncovered_client_scope_reads_its_coins_from_the_chain() {
        let client_ph = "aa".repeat(32);
        let (be, _fb) = uncovered_but_funded_client(&client_ph).await;

        let (_s, body) = be
            .dispatch("get_coins", r#"{"offset":0,"limit":100}"#)
            .await;
        let r: GetCoinsResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(
            r.coins
                .iter()
                .map(|c| c.amount.to_u64().unwrap())
                .sum::<u64>(),
            1_599_000_000_000,
            "an uncovered scope was served the replica's empty coin set instead of the chain's"
        );
    }

    /// **The control: a COVERED client scope still reads from the replica and still says synced.**
    ///
    /// Without this, the two assertions above are satisfied by an implementation that simply never
    /// reports synced — which would be honest and useless.
    #[tokio::test]
    async fn a_covered_client_scope_still_reads_from_the_replica_and_reports_synced() {
        let client_ph = "aa".repeat(32);
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[coin_at("c1", &client_ph, 4_200)])
            .await
            .unwrap();
        db.record_coverage(&CoveredSet::from_hex([client_ph.as_str()]))
            .await
            .unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );
        let addr = encode_address(&client_ph, "xch").unwrap();
        be.dispatch(
            "login",
            &format!(r#"{{"fingerprint":1,"addresses":["{addr}"]}}"#),
        )
        .await;

        let (_s, body) = be.dispatch("get_sync_status", "{}").await;
        let r: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(r.selectable_balance.to_u64(), Some(4_200));
        assert_eq!(
            (r.synced_coins, r.total_coins),
            (1, 1),
            "a covered scope must still report a complete view"
        );
    }

    // ---- the token reads are gated on coverage too (dig-node#247) ---------
    //
    // dig-node#246 gave `get_coins` and `get_sync_status` the containment gate. `token_record`
    // never got it, and THREE more RPCs reach it -- `get_token`, `get_cats`, `get_all_cats` --
    // so the same client that #246 was written for still saw a confident `0` on whichever of
    // those surfaces dig-app happened to read. `TokenRecord` carries no completeness field, so
    // its zero has nothing standing beside it to qualify it.
    //
    // Every fixture below reuses `uncovered_but_funded_client`, which holds the three properties
    // that make the defect visible at all: the money is on the CHAIN and not in the replica, the
    // coverage that WAS recorded is over a DIFFERENT address, and `db.is_synced()` is true. Drop
    // any one and the test can no longer tell "zero because unscoped" from "zero because empty".

    /// **Regression (dig-node#247): the XCH token balance falls to the chain for an uncovered
    /// scope rather than answering a confident zero.**
    #[tokio::test]
    async fn an_uncovered_client_scope_is_never_told_its_xch_token_balance_is_zero() {
        let client_ph = "aa".repeat(32);
        let (be, _fb) = uncovered_but_funded_client(&client_ph).await;

        let (status, body) = be.dispatch("get_token", r#"{"asset_id":null}"#).await;
        assert_eq!(status, 200, "{body}");
        let r: GetTokenResponse = serde_json::from_str(&body).unwrap();
        let token = r.token.expect("XCH is always a token");
        assert_eq!(
            token.balance.to_u64(),
            Some(1_599_000_000_000),
            "an uncovered scope was served the replica's zero instead of the chain's balance"
        );
        assert_eq!(
            token.selectable_balance.to_u64(),
            Some(1_599_000_000_000),
            "`selectable_balance` kept the confident zero that `balance` no longer reports"
        );
    }

    /// **Regression (dig-node#247): a CAT balance is REFUSED for an uncovered scope.**
    ///
    /// The CAT case cannot take the XCH remedy. Attributing a CAT coin to its asset id needs
    /// puzzle uncurrying, which the fallback tier does not do, so routing a CAT read to the chain
    /// would return an empty set — the same confident zero through a different door. Refusing is
    /// the only honest answer this wire type can currently express, and it is a NON-200 the caller
    /// cannot mistake for a figure.
    #[tokio::test]
    async fn an_uncovered_client_scope_refuses_to_answer_a_cat_token_balance() {
        let client_ph = "aa".repeat(32);
        let (be, _fb) = uncovered_but_funded_client(&client_ph).await;

        let (status, body) = be
            .dispatch(
                "get_token",
                &format!(r#"{{"asset_id":"{}"}}"#, "cc".repeat(32)),
            )
            .await;
        assert_eq!(
            status, 503,
            "an uncovered CAT balance was ANSWERED rather than refused; body was {body}"
        );
    }

    /// **Regression (dig-node#247): `get_cats` is refused for an uncovered scope.**
    ///
    /// Left ungated it returns an empty LIST, which reads as "you own no CATs" — a falsehood of
    /// exactly the same class as the zero, and one that no per-token gate downstream can repair,
    /// because the list it iterates is itself read out of the replica.
    #[tokio::test]
    async fn an_uncovered_client_scope_refuses_to_list_its_cats() {
        let client_ph = "aa".repeat(32);
        let (be, _fb) = uncovered_but_funded_client(&client_ph).await;

        let (status, body) = be.dispatch("get_cats", "{}").await;
        assert_eq!(
            status, 503,
            "an uncovered scope was told it owns no CATs; body was {body}"
        );
    }

    /// **An uncovered scope with NO live chain source refuses rather than reporting zero.**
    ///
    /// The XCH remedy above is a ROUTE, and a route needs somewhere to go. With the replica not
    /// covering the scope and no chain source attached, nothing in the node knows the balance —
    /// so the one answer it must not give is a number.
    #[tokio::test]
    async fn an_uncovered_scope_with_no_chain_source_refuses_rather_than_reporting_zero() {
        let client_ph = "aa".repeat(32);
        let db = WalletDb::open_in_memory().await.unwrap();
        db.record_coverage(&CoveredSet::from_hex(["bb".repeat(32).as_str()]))
            .await
            .unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default().offline()),
            WalletConfig::default(),
        );
        let addr = encode_address(&client_ph, "xch").unwrap();
        be.dispatch(
            "login",
            &format!(r#"{{"fingerprint":1,"addresses":["{addr}"]}}"#),
        )
        .await;

        let (status, body) = be.dispatch("get_token", r#"{"asset_id":null}"#).await;
        assert_eq!(
            status, 503,
            "a node with no replica coverage and no chain source still reported a balance; \
             body was {body}"
        );
    }

    /// **CONTROL: a COVERED scope still answers from the replica, for XCH and for a CAT.**
    ///
    /// Without this, all four assertions above are satisfied by an implementation that refuses
    /// every token read — honest, and useless. It is also what makes the CAT refusal a statement
    /// about COVERAGE rather than about CATs.
    #[tokio::test]
    async fn a_covered_client_scope_still_reads_its_token_balances_from_the_replica() {
        let client_ph = "aa".repeat(32);
        let asset = "cc".repeat(32);
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[coin_at("c1", &client_ph, 4_200)])
            .await
            .unwrap();
        let mut cat = coin_at("c2", &"dd".repeat(32), 300);
        cat.asset_id = Some(asset.clone());
        cat.hint = Some(client_ph.clone());
        db.upsert_coins(&[cat]).await.unwrap();
        db.record_coverage(&CoveredSet::from_hex([client_ph.as_str()]))
            .await
            .unwrap();
        db.force_initial_sync_complete_for_test(true).await.unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );
        let addr = encode_address(&client_ph, "xch").unwrap();
        be.dispatch(
            "login",
            &format!(r#"{{"fingerprint":1,"addresses":["{addr}"]}}"#),
        )
        .await;

        let (status, body) = be.dispatch("get_token", r#"{"asset_id":null}"#).await;
        assert_eq!(status, 200, "{body}");
        let r: GetTokenResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(r.token.unwrap().balance.to_u64(), Some(4_200));

        let (status, body) = be
            .dispatch("get_token", &format!(r#"{{"asset_id":"{asset}"}}"#))
            .await;
        assert_eq!(status, 200, "{body}");
        let r: GetTokenResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(
            r.token.unwrap().balance.to_u64(),
            Some(300),
            "a covered scope must still be answered its CAT balance"
        );

        let (status, body) = be.dispatch("get_cats", "{}").await;
        assert_eq!(status, 200, "{body}");
        let r: GetCatsResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(r.cats.len(), 1, "a covered scope must still list its CATs");
    }

    // ---- in-flight coin reservation + real pending set (#2763 / #2764) ------
    //
    // These drive the PRODUCTION reads (`spendable_coins`, `get_pending_transactions`), not the
    // database primitives underneath them. The primitives already have their own tests in `db.rs`
    // and passed while nothing called them: the defect these close is that the wiring did not
    // exist, so a test that stops at the DB layer cannot see it.

    /// A coin row with real hex, so `singleton::coin_from_row` can parse it.
    fn spendable_row(id_byte: u8, amount: u64) -> CoinRow {
        CoinRow {
            coin_id: format!("{id_byte:02x}").repeat(32),
            parent_coin_info: "11".repeat(32),
            puzzle_hash: test_ph(),
            amount: amount.to_string(),
            created_height: Some(1),
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    fn pending_row(
        tx: &str,
        coin_ids: &[String],
        fee: Option<&str>,
        expires_at: i64,
    ) -> PendingTransactionRow {
        PendingTransactionRow {
            transaction_id: tx.into(),
            bundle_hex: "00".into(),
            fee: fee.map(Into::into),
            submitted_at: 1_000,
            expires_at,
            attempts: 1,
            reserved_coin_ids: coin_ids.to_vec(),
        }
    }

    /// **The defect (#2763), at the seam that actually selects.** A coin committed to a pushed,
    /// unsettled bundle must not be offered to the next spend — while still counting as money the
    /// wallet owns, because the chain has not said otherwise yet.
    #[tokio::test]
    async fn a_reserved_coin_leaves_selection_but_not_the_balance() {
        let (a, b) = (spendable_row(0xa1, 100), spendable_row(0xb2, 500));
        let be = backend_with(vec![a.clone(), b.clone()], true).await;
        let far_future = super::super::custody::now_ms() as i64 + 600_000;
        be.db
            .reserve_spend(&pending_row(
                "tx1",
                std::slice::from_ref(&a.coin_id),
                Some("7"),
                far_future,
            ))
            .await
            .unwrap();

        let selectable = be.spendable_coins(None).await.unwrap();
        assert_eq!(
            selectable.len(),
            1,
            "the reserved coin was offered to a second spend"
        );
        assert_eq!(selectable[0].amount, 500);

        assert_eq!(
            be.db.unspent_coins(None).await.unwrap().len(),
            2,
            "reserving a coin must not remove it from what the wallet owns"
        );
    }
    /// A bundle spending exactly the coin `spendable_row(id_byte, amount)` describes, in the hex
    /// form the wire carries — returned alongside the ids the production path will derive from it.
    ///
    /// The row and the bundle MUST agree on the coin's identity or the reservation writes an id
    /// nothing selects on, and a test built that way passes while reserving the wrong coin.
    /// Deriving the row's `coin_id` FROM the same `Coin` the bundle spends is what makes that
    /// agreement structural instead of a matching pair of literals.
    fn a_bundle_spending(row: &mut CoinRow) -> (String, String) {
        use chia_protocol::{Bytes32, Coin, CoinSpend, Program, SpendBundle};
        let coin = Coin::new(
            Bytes32::new(hex_32(&row.parent_coin_info)),
            Bytes32::new(hex_32(&row.puzzle_hash)),
            row.amount.parse().unwrap(),
        );
        row.coin_id = hex::encode(coin.coin_id());
        let spend = CoinSpend::new(coin, Program::from(vec![0x01]), Program::from(vec![0x80]));
        let bundle = SpendBundle::new(vec![spend], Default::default());
        (
            super::super::chain::encode_signed_bundle(&bundle).unwrap(),
            hex::encode(bundle.name()),
        )
    }

    fn hex_32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// **Proves the WIRING, at the only seam that has it (#251).** A bundle the mempool accepted
    /// leaves its inputs reserved — reached by PUSHING, not by calling `reserve_spend` directly.
    ///
    /// Every other reservation test drives `db.reserve_spend(...)` itself, so all of them pass
    /// with the `push -> reserve` call deleted: mutating the seam to `if false && outcome.accepted`
    /// left the whole suite green. That is the same argument this module already makes for #250 —
    /// the defect is that the wiring did not exist, so a test stopping at the DB layer cannot see
    /// it — applied to the half that was still only tested from below.
    ///
    /// FIXTURE DESIGN. Two spendable coins, and the bundle spends exactly ONE of them. A single
    /// coin cannot distinguish "the pushed bundle's input was reserved" from "selection was
    /// emptied", which a mis-scoped reservation would satisfy identically; the untouched control
    /// coin must survive, and it is what turns the assertion from a count into a claim about
    /// WHICH coin. Both observations go through the PRODUCTION reads (`spendable_coins`,
    /// `get_pending_transactions`) rather than the DB primitives beneath them, and the recorded
    /// transaction id is checked against the bundle's own name so a reservation filed under some
    /// other id cannot pass.
    #[tokio::test]
    async fn a_pushed_bundle_reserves_its_inputs_through_the_production_path() {
        let mut spent_by_the_bundle = spendable_row(0xa1, 100);
        let (bundle_hex, transaction_id) = a_bundle_spending(&mut spent_by_the_bundle);
        let untouched = spendable_row(0xb2, 500);
        let be = backend_with(vec![spent_by_the_bundle.clone(), untouched.clone()], true)
            .await
            .with_pusher(FakePusher::accepting());

        assert_eq!(
            be.spendable_coins(None).await.unwrap().len(),
            2,
            "the fixture must start with BOTH coins selectable, or the assertion below is vacuous"
        );

        let outcome = be.push_signed_bundle(&bundle_hex).await.unwrap();
        assert!(outcome.accepted, "the fixture's pusher accepts");

        let pending = be.get_pending_transactions().await.unwrap().transactions;
        assert_eq!(
            pending.len(),
            1,
            "an accepted push recorded nothing in flight; the reserve call is not wired to it"
        );
        assert_eq!(
            pending[0].transaction_id, transaction_id,
            "the in-flight record is filed under an id that is not the bundle's"
        );

        let selectable = be.spendable_coins(None).await.unwrap();
        assert_eq!(
            selectable.len(),
            1,
            "the pushed bundle's input is still offered to a second spend"
        );
        assert_eq!(
            selectable[0].amount, 500,
            "the wrong coin was reserved: the untouched control left selection"
        );
    }

    /// **Proves:** a bundle denied WITHOUT a stated reason is held to the TTL, not returned to the
    /// selectable set (#348).
    ///
    /// **Catches:** the shipped fail-open. Reservation was gated on `outcome.accepted` alone, so a
    /// source that denied relaying what it actually relayed left the coins reselectable while a
    /// bundle carrying them was in flight — a second send inside the confirmation window could
    /// reselect the same inputs. Under NC-12 every dialled peer is untrusted, so a false denial is
    /// the assumed case rather than an exotic one, and it was the CHEAP direction to lie in.
    ///
    /// FIXTURE DESIGN. This differs from `a_refused_bundle_reserves_nothing` in EXACTLY one field —
    /// `rejection` is `None` rather than `Some(...)` — and the two tests demand OPPOSITE outcomes.
    /// That pairing is the whole property: it is what distinguishes "held because the denial was
    /// unexplained" from "holds on every refusal", which would be the lockout regression. Two
    /// coins, one spent by the bundle, so a mis-scoped reservation that empties selection cannot
    /// pass for a correct one.
    #[tokio::test]
    async fn a_bundle_denied_without_a_reason_is_held_rather_than_freed() {
        let mut spent_by_the_bundle = spendable_row(0xa1, 100);
        let (bundle_hex, transaction_id) = a_bundle_spending(&mut spent_by_the_bundle);
        let untouched = spendable_row(0xb2, 500);
        // A bare denial: the source says "no" and does not say why. Indistinguishable, from here,
        // from a source denying a relay it performed.
        let silently_denying = FakePusher::answering(Ok(PushOutcome {
            accepted: false,
            transaction_id: None,
            // A refusal that states NO reason -- the shape the #348 hold keys on.
            rejection: None,
            verdict: "PENDING".into(),
        }));
        let be = backend_with(vec![spent_by_the_bundle.clone(), untouched.clone()], true)
            .await
            .with_pusher(silently_denying);

        assert_eq!(
            be.spendable_coins(None).await.unwrap().len(),
            2,
            "the fixture must start with BOTH coins selectable, or the assertion below is vacuous"
        );

        let outcome = be.push_signed_bundle(&bundle_hex).await.unwrap();
        assert!(
            !outcome.accepted,
            "the outcome is reported honestly — the fix changes what is RESERVED, not what is said"
        );

        let pending = be.get_pending_transactions().await.unwrap().transactions;
        assert_eq!(
            pending.len(),
            1,
            "an unexplained denial left the bundle unrecorded; its inputs are reselectable while it \
             may be in flight"
        );
        assert_eq!(pending[0].transaction_id, transaction_id);

        let selectable = be.spendable_coins(None).await.unwrap();
        assert_eq!(
            selectable.len(),
            1,
            "the possibly-in-flight bundle's input is still offered to a second spend"
        );
        assert_eq!(
            selectable[0].amount, 500,
            "the wrong coin was held: the untouched control left selection"
        );
    }

    /// **Proves:** a transport failure is treated as POSSIBLY IN FLIGHT — the inputs are held —
    /// while the caller still receives the honest error (#348).
    ///
    /// **Catches:** the other half of the fail-open. `push()` returning `Err` propagated with `?`
    /// BEFORE any reservation, so a transport that failed after transmitting freed the coins. The
    /// node cannot tell "never sent" from "sent, and the acknowledgement was lost", and only one of
    /// those is safe to free.
    ///
    /// The error assertion is load-bearing in the other direction: a fix that swallowed the failure
    /// to reach the reserve call would report a push that never happened as a success, which is the
    /// money-lie this contract refuses. Both must hold at once.
    #[tokio::test]
    async fn a_transport_failure_holds_the_inputs_and_still_reports_the_failure() {
        let mut spent_by_the_bundle = spendable_row(0xa1, 100);
        let (bundle_hex, transaction_id) = a_bundle_spending(&mut spent_by_the_bundle);
        let untouched = spendable_row(0xb2, 500);
        let unreachable = FakePusher::answering(Err("connection reset".into()));
        let be = backend_with(vec![spent_by_the_bundle.clone(), untouched.clone()], true)
            .await
            .with_pusher(unreachable);

        assert_eq!(be.spendable_coins(None).await.unwrap().len(), 2);

        let err = be
            .push_signed_bundle(&bundle_hex)
            .await
            .expect_err("a transport failure must still be reported as a failure");
        assert!(
            matches!(err, PushError::Unreachable(_)),
            "the caller must learn the network was not reached, got {err:?}"
        );

        let pending = be.get_pending_transactions().await.unwrap().transactions;
        assert_eq!(
            pending.len(),
            1,
            "a post-transmit transport failure freed the inputs of a bundle that may be in flight"
        );
        assert_eq!(pending[0].transaction_id, transaction_id);

        let selectable = be.spendable_coins(None).await.unwrap();
        assert_eq!(selectable.len(), 1);
        assert_eq!(selectable[0].amount, 500, "the wrong coin was held");
    }

    /// **The control:** a mempool refusal that STATES ITS REASON reserves nothing.
    ///
    /// Without it, reserving unconditionally satisfies the tests above while stranding a user's
    /// coins over a spend that will never happen — the lockout that is the worse of the two
    /// failures. It pins the guard, not just the wiring.
    ///
    /// Since #348 this is the ONLY path that frees the inputs, and it is the sibling of
    /// `a_bundle_denied_without_a_reason_is_held_rather_than_freed`: the two fixtures differ in the
    /// `rejection` field alone and demand opposite outcomes, so together they pin the bound from
    /// both sides. Neither is meaningful without the other.
    #[tokio::test]
    async fn a_refused_bundle_reserves_nothing() {
        let mut refused = spendable_row(0xa1, 100);
        let (bundle_hex, _) = a_bundle_spending(&mut refused);
        let refusing = FakePusher::answering(Ok(PushOutcome {
            accepted: false,
            transaction_id: None,
            rejection: Some("mempool said no".into()),
            verdict: "FAILED".into(),
        }));
        let be = backend_with(vec![refused.clone()], true)
            .await
            .with_pusher(refusing);

        let outcome = be.push_signed_bundle(&bundle_hex).await.unwrap();
        assert!(!outcome.accepted);

        assert!(
            be.get_pending_transactions()
                .await
                .unwrap()
                .transactions
                .is_empty(),
            "a refused bundle was recorded as in flight"
        );
        assert_eq!(
            be.spendable_coins(None).await.unwrap().len(),
            1,
            "a refused bundle stranded the coins it never committed"
        );
    }

    /// **The defect (#2764).** `get_pending_transactions` returned a hardcoded empty list. A
    /// caller that pushed a bundle and polled was told, as a measured fact, that nothing was in
    /// flight.
    #[tokio::test]
    async fn pending_transactions_reports_an_in_flight_bundle() {
        let a = spendable_row(0xa1, 100);
        let be = backend_with(vec![a.clone()], true).await;
        let far_future = super::super::custody::now_ms() as i64 + 600_000;
        be.db
            .reserve_spend(&pending_row(
                "tx1",
                std::slice::from_ref(&a.coin_id),
                Some("7"),
                far_future,
            ))
            .await
            .unwrap();

        let pending = be.get_pending_transactions().await.unwrap().transactions;
        assert_eq!(
            pending.len(),
            1,
            "a pushed bundle was reported as nothing in flight"
        );
        assert_eq!(pending[0].transaction_id, "tx1");
        assert_eq!(pending[0].fee, Some(Amount::u64(7)));
    }

    /// A fee this node could not compute is reported as `null`, NEVER as zero. The node relays
    /// bundles it did not build (§908), and a confident zero would be a claim about someone
    /// else's money.
    #[tokio::test]
    async fn an_uncomputable_fee_is_reported_as_null_not_zero() {
        let a = spendable_row(0xa1, 100);
        let be = backend_with(vec![a.clone()], true).await;
        let far_future = super::super::custody::now_ms() as i64 + 600_000;
        be.db
            .reserve_spend(&pending_row(
                "tx1",
                std::slice::from_ref(&a.coin_id),
                None,
                far_future,
            ))
            .await
            .unwrap();

        let pending = be.get_pending_transactions().await.unwrap().transactions;
        assert_eq!(
            pending[0].fee, None,
            "an unknown fee was flattened to a number"
        );
    }

    /// A reservation ALWAYS lapses, and both surfaces observe the lapse: the bundle stops being
    /// reported in flight, and its coin returns to selection. This is the failure direction that
    /// would otherwise be worse than the bug — a release path that never runs must not be able to
    /// strand the user's money permanently.
    #[tokio::test]
    async fn an_expired_reservation_stops_being_pending_and_frees_its_coin() {
        let a = spendable_row(0xa1, 100);
        let be = backend_with(vec![a.clone()], true).await;
        be.db
            .reserve_spend(&pending_row(
                "tx1",
                std::slice::from_ref(&a.coin_id),
                Some("7"),
                1,
            ))
            .await
            .unwrap();

        assert!(
            be.get_pending_transactions()
                .await
                .unwrap()
                .transactions
                .is_empty(),
            "a lapsed bundle was still reported in flight"
        );
        assert_eq!(
            be.spendable_coins(None).await.unwrap().len(),
            1,
            "a lapsed reservation stranded the coin"
        );
    }
}
