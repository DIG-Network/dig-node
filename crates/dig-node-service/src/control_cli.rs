//! CLI parity with the node's `control.*` surface (#426).
//!
//! The DIG Chrome extension drives the node over the token-gated `control.*` WS/RPC surface
//! (status, config, cache, hosted stores, §21 sync, the auto-update beacon, subscriptions).
//! This module gives the `dig-node` / `dign` CLI a subcommand for EVERY one of those controls,
//! so an operator (or an agent) can drive the node from a terminal exactly as the extension
//! does from a browser — with `--json` machine output beside the human summary.
//!
//! # No forked logic — thin dispatch over the ONE control plane
//!
//! Every action here is a THIN dispatch: it calls the SAME `control.*` method the extension
//! calls, through the shared [`crate::control_client::call_control`] client (master-token auth
//! over loopback — the identical gate, never an unauthenticated backdoor). The node owns the
//! behaviour; this module only maps a subcommand to a method + renders the result. So the CLI
//! and the extension can never drift in WHAT they do — only in HOW they present it.
//!
//! # Staying in sync with the extension surface
//!
//! [`crate::control::CONTROL_METHODS`] is the canonical control-method set; every method there
//! MUST be reachable from a CLI verb ([`cli_covered_control_methods`]). The drift test at the
//! bottom of this module fails if a new `control.*` method is added to the node without a CLI
//! verb — so the parity is enforced mechanically, not by memory.

use serde_json::{json, Value};

use crate::cli::Outcome;
use crate::config::Config;
use crate::control_client::call_control;
use dig_node_control_interface::results::{CollateralBufferResult, CollateralFundingState};

/// One control-parity CLI action, clap-agnostic (mapped from the subcommand in `entrypoint.rs`).
/// Each variant names the single `control.*` method it dispatches — see [`ControlAction::method`].
pub enum ControlAction {
    /// `control.status` — the rich at-a-glance node status (version, uptime, cache, hosted
    /// stores, sync availability). Distinct from `dig-node status`, which is an UNAUTHENTICATED
    /// liveness probe of `/health`; this is the token-gated detailed view the extension shows.
    Info,
    /// `control.config.get` — the node's effective config (addr/port, upstream, cache dir).
    ConfigGet,
    /// `control.config.setUpstream` — persist the upstream DIG RPC override (next-start effective).
    ConfigSetUpstream { url: String },
    /// `control.cache.get` — cache cap/used/dir/shared.
    CacheGet,
    /// `control.cache.setCap` — set the on-disk cache size cap (bytes; floored at 64 MiB).
    CacheSetCap { bytes: u64 },
    /// `control.cache.clear` — delete all locally cached DIG content.
    CacheClear,
    /// `control.hostedStores.list` — every hosted/pinned store + its cached capsules.
    StoresList,
    /// `control.hostedStores.pin` — pin a store (`storeId[:rootHash]`) + pre-fetch when possible.
    StoresPin { store: String },
    /// `control.hostedStores.unpin` — unpin a store + evict its cached capsules.
    StoresUnpin { store: String },
    /// `control.hostedStores.status` — one store's pin/cache status.
    StoresStatus { store: String },
    /// `control.capsule.fetch` — start a P2P whole-capsule pull for `store` + `root`.
    CapsuleFetch { store: String, root: String },
    /// `control.sync.status` — §21 whole-store sync availability + pinned coverage.
    SyncStatus,
    /// `control.sync.trigger` — trigger a §21 sync for one capsule (`storeId:rootHash`).
    SyncTrigger { store: String },
    /// `control.wallet.balance` — the READ-ONLY balance of a public address (XCH or $DIG).
    WalletBalance { address: String, asset: String },
    /// `control.wallet.coins` — ONE PAGE of the READ-ONLY unspent coins of a public address (XCH
    /// or $DIG). `after_coin_id` resumes from the `cursor` of a previous page.
    WalletCoins {
        address: String,
        asset: String,
        after_coin_id: Option<String>,
        limit: Option<u32>,
    },
    /// `control.wallet.coinById` — the READ-ONLY lookup of ONE coin by coin id (spent or not).
    WalletCoinById { coin_id: String },
    /// `control.wallet.coinSpend` — the READ-ONLY spend that spent one coin (reveal + solution).
    WalletCoinSpend { coin_id: String },
    /// `control.wallet.coinsByParent` — ONE PAGE of the READ-ONLY direct children one coin's
    /// spend created. `after_coin_id` resumes from the `cursor` of a previous page.
    WalletCoinsByParent {
        parent_coin_id: String,
        after_coin_id: Option<String>,
        limit: Option<u32>,
    },
    /// `control.wallet.arrivals` — the READ-ONLY incoming funds confirmed since a cursor.
    WalletArrivals { after_seq: i64, limit: i64 },
    /// `control.wallet.syncStatus` — the READ-ONLY wallet chain-sync phase, replica height and
    /// Chia peer count. Distinct from `control.sync.status`, which is about DIG stores.
    WalletSyncStatus,
    /// `control.wallet.peak` — the READ-ONLY chain peak height the node can see.
    WalletPeak,
    /// `control.wallet.broadcast` — push an ALREADY-SIGNED spend bundle. The node signs nothing.
    WalletBroadcast { signed_bundle_hex: String },
    /// `control.wallet.watch` — register PUBLIC keys whose addresses this node should follow.
    /// Public keys only: no seed crosses and nothing here gains a signing capability (§908).
    WalletWatch { public_keys: Vec<String> },
    /// `control.wallet.unwatch` — stop following the addresses of these public keys.
    WalletUnwatch { public_keys: Vec<String> },
    /// `control.wallet.watched` — the public keys this node is currently following.
    WalletWatched,
    /// `control.wallet.reservations.held` — the coins committed to in-flight spends.
    ///
    /// No arguments by design: a caller-supplied instant would be a lapse oracle, so the node
    /// reads its own clock (dig_ecosystem#3127).
    WalletReservationsHeld,
    /// `control.wallet.reservations.reserve` — hold coins against selection, all of them or none.
    ///
    /// Bookkeeping only: coin ids are public chain facts, and this carries no key (§908).
    WalletReservationsReserve {
        /// The coin ids to hold.
        coin_ids: Vec<String>,
        /// The requested lifetime. The node clamps it and reports what it APPLIED.
        ttl_secs: Option<u64>,
    },
    /// `control.wallet.reservations.release` — free a hold ahead of its TTL.
    WalletReservationsRelease {
        /// The opaque handle returned by a reserve.
        reservation_id: String,
    },
    /// `control.profile.putBody` — hand this node a profile body to persist and serve.
    ///
    /// The node checks the root on chain and refuses a body it cannot confirm (SPEC §22.3); this
    /// verb carries no key and signs nothing (§908).
    ProfilePutBody {
        /// The profile's store id, lowercase 64-hex.
        store_id: String,
        /// The root the body is claimed to hash to, lowercase 64-hex. Checked, never trusted.
        root: String,
        /// The body itself, standard padded base64 of its DPB serialization.
        body_b64: String,
    },
    /// `control.profile.getBody` — read the profile body this node holds at a store id + root.
    ProfileGetBody {
        /// The profile's store id, lowercase 64-hex.
        store_id: String,
        /// The root to read at, lowercase 64-hex.
        root: String,
    },
    /// `control.updater.status` — the DIG auto-update beacon's status.
    UpdaterStatus,
    /// `control.updater.setChannel` — set the beacon channel (`nightly` | `stable`).
    UpdaterSetChannel { channel: String },
    /// `control.updater.pause` — pause auto-updates (optionally until a unix-seconds deadline).
    UpdaterPause { until: Option<u64> },
    /// `control.updater.resume` — resume auto-updates.
    UpdaterResume,
    /// `control.updater.checkNow` — check for an update now.
    UpdaterCheckNow,
    /// `control.listSubscriptions` — the node's persisted store-subscription set.
    SubsList,
    /// `control.subscribe` — subscribe the node to a store id (chain-watch + gap-fill).
    SubsAdd { store_id: String },
    /// `control.unsubscribe` — remove a store subscription.
    SubsRemove { store_id: String },
    /// `control.chiaPeers.add` — start TRUSTING a Chia full node.
    ///
    /// A different network from `control.peers.*`, which are DIG gossip peers, and a different
    /// kind of act: this one grants authority. See [`ControlAction::ChiaPeersList`].
    ChiaPeersAdd { ip: String },
    /// `control.chiaPeers.list` — the tracked Chia full-node peers, with the `user_managed` flag
    /// that says which of them are trusted without corroboration.
    ChiaPeersList,
    /// `control.collateral.requirement` — this epoch's per-store collateral requirement, with the
    /// census inputs behind it, or a NAMED reason the node cannot state it.
    ///
    /// The answer is consensus-derived and identical on every node. It carries no safety margin:
    /// the margin is this operator's local preference, and folding it in here would make a private
    /// choice look like the network's price.
    CollateralRequirement,
    /// `control.collateral.margin.get` — the node's local safety margin, in basis points.
    CollateralMarginGet,
    /// `control.collateral.buffer` — the node's OWN answer: what it recommends holding and
    /// the funding state it is in, from the served set and balance the node itself knows.
    ///
    /// Distinct from the operator-supplied form of `dign collateral buffer`, which computes the
    /// same figures from operands a person types. The node is authoritative; the operands exist
    /// so a person can get a number before the node can enumerate its own served set.
    CollateralBuffer,
    /// `control.collateral.margin.set` — persist the local safety margin.
    ///
    /// The node is the authoritative home for this setting: the flywheel is headless, so a machine
    /// with no GUI must be able to set it from the command line.
    CollateralMarginSet {
        /// The margin in BASIS POINTS (`100` is +1%), already resolved from any preset name.
        margin_bp: u64,
    },
    /// `control.mirror.bondStates` — one page of this node's mirror bonds (SPEC.md §25.8).
    ///
    /// Paged rather than whole because the node's answer is paged: a headless operator walking the
    /// set from the command line resumes from the cursor the node HANDED them, exactly as any other
    /// client does. The locked-$DIG total the node reports spans the WHOLE set, so a person reading
    /// one page is never reading a partial money figure.
    MirrorBondStates {
        /// Resume strictly after this `(store_id, root)`, as the node handed it back.
        after: Option<(String, String)>,
        /// The page size, or `None` for the contract's default.
        limit: Option<u32>,
    },
    /// `control.chiaPeers.remove` — stop trusting a Chia full node (`ban` keeps it excluded so
    /// discovery cannot re-add it).
    ChiaPeersRemove { ip: String, ban: bool },
}

impl ControlAction {
    /// The `control.*` method this action dispatches. The single place the action↔method
    /// mapping lives, so [`cli_covered_control_methods`] and [`run`] never disagree.
    pub fn method(&self) -> &'static str {
        match self {
            ControlAction::Info => "control.status",
            ControlAction::ConfigGet => "control.config.get",
            ControlAction::ConfigSetUpstream { .. } => "control.config.setUpstream",
            ControlAction::CacheGet => "control.cache.get",
            ControlAction::CacheSetCap { .. } => "control.cache.setCap",
            ControlAction::CacheClear => "control.cache.clear",
            ControlAction::StoresList => "control.hostedStores.list",
            ControlAction::StoresPin { .. } => "control.hostedStores.pin",
            ControlAction::StoresUnpin { .. } => "control.hostedStores.unpin",
            ControlAction::StoresStatus { .. } => "control.hostedStores.status",
            ControlAction::CapsuleFetch { .. } => "control.capsule.fetch",
            ControlAction::SyncStatus => "control.sync.status",
            ControlAction::SyncTrigger { .. } => "control.sync.trigger",
            ControlAction::WalletBalance { .. } => "control.wallet.balance",
            ControlAction::WalletCoins { .. } => "control.wallet.coins",
            ControlAction::WalletCoinById { .. } => "control.wallet.coinById",
            ControlAction::WalletCoinSpend { .. } => "control.wallet.coinSpend",
            ControlAction::WalletCoinsByParent { .. } => "control.wallet.coinsByParent",
            ControlAction::WalletArrivals { .. } => "control.wallet.arrivals",
            ControlAction::WalletPeak => "control.wallet.peak",
            ControlAction::WalletSyncStatus => "control.wallet.syncStatus",
            ControlAction::WalletBroadcast { .. } => "control.wallet.broadcast",
            ControlAction::WalletWatch { .. } => "control.wallet.watch",
            ControlAction::WalletUnwatch { .. } => "control.wallet.unwatch",
            ControlAction::WalletWatched => "control.wallet.watched",
            ControlAction::WalletReservationsHeld => "control.wallet.reservations.held",
            ControlAction::WalletReservationsReserve { .. } => {
                "control.wallet.reservations.reserve"
            }
            ControlAction::WalletReservationsRelease { .. } => {
                "control.wallet.reservations.release"
            }
            ControlAction::ProfilePutBody { .. } => "control.profile.putBody",
            ControlAction::ProfileGetBody { .. } => "control.profile.getBody",
            ControlAction::UpdaterStatus => "control.updater.status",
            ControlAction::UpdaterSetChannel { .. } => "control.updater.setChannel",
            ControlAction::UpdaterPause { .. } => "control.updater.pause",
            ControlAction::UpdaterResume => "control.updater.resume",
            ControlAction::UpdaterCheckNow => "control.updater.checkNow",
            ControlAction::SubsList => "control.listSubscriptions",
            ControlAction::SubsAdd { .. } => "control.subscribe",
            ControlAction::SubsRemove { .. } => "control.unsubscribe",
            ControlAction::ChiaPeersAdd { .. } => "control.chiaPeers.add",
            ControlAction::ChiaPeersList => "control.chiaPeers.list",
            ControlAction::CollateralRequirement => "control.collateral.requirement",
            ControlAction::CollateralMarginGet => "control.collateral.margin.get",
            ControlAction::CollateralBuffer => "control.collateral.buffer",
            ControlAction::CollateralMarginSet { .. } => "control.collateral.margin.set",
            ControlAction::MirrorBondStates { .. } => "control.mirror.bondStates",
            ControlAction::ChiaPeersRemove { .. } => "control.chiaPeers.remove",
        }
    }

    /// The JSON-RPC params for this action (an empty object for the read/no-arg methods).
    ///
    /// Public so a test can assert that a parsed command line's operands actually reach the wire,
    /// not merely that it selected the right method (see `entrypoint`'s parser tests).
    pub fn wire_params(&self) -> Value {
        /// A `--asset` operand as the wire form the control plane parses (dig_ecosystem#3077).
        ///
        /// `xch` and `dig` travel as themselves. A bare 64-hex asset id becomes the tagged
        /// `{"cat":"<hex>"}` form, so a person can read an ARBITRARY CAT from the command line —
        /// without that, the widened wire would be reachable only by a program.
        ///
        /// Anything else is forwarded UNCHANGED, to be refused by the node's own parser. This CLI
        /// deliberately does not decide what an asset is: a second, laxer opinion here is how a
        /// typo becomes a read of the wrong token.
        fn asset_to_wire(asset: &str) -> Value {
            let looks_like_an_asset_id =
                asset.len() == 64 && asset.bytes().all(|b| b.is_ascii_hexdigit());
            if looks_like_an_asset_id {
                json!({ "cat": asset })
            } else {
                Value::String(asset.to_string())
            }
        }

        match self {
            ControlAction::ConfigSetUpstream { url } => json!({ "upstream": url }),
            // Basis points, never a percentage and never a float. A 1 bp margin (0.01%) is a legal
            // choice and any conversion to whole percent would erase it.
            ControlAction::CollateralMarginSet { margin_bp } => json!({ "margin_bp": margin_bp }),
            // Both page fields are OMITTED when unset rather than sent as null, so the node
            // applies the CONTRACT's default page size rather than one this CLI invented.
            ControlAction::MirrorBondStates { after, limit } => {
                let mut params = json!({});
                if let Some((store_id, root)) = after {
                    params["after"] = json!({ "store_id": store_id, "root": root });
                }
                if let Some(limit) = limit {
                    params["limit"] = json!(limit);
                }
                params
            }
            ControlAction::CacheSetCap { bytes } => json!({ "cap_bytes": bytes }),
            ControlAction::StoresPin { store }
            | ControlAction::StoresUnpin { store }
            | ControlAction::StoresStatus { store }
            | ControlAction::SyncTrigger { store } => json!({ "store": store }),
            // The contract names these `store` and `root` SEPARATELY rather than as one
            // `storeId:rootHash` reference, because a capsule fetch always needs a concrete
            // generation; folding it into the `store` arm above would send one joined field the
            // node refuses as a missing `root`.
            ControlAction::CapsuleFetch { store, root } => json!({ "store": store, "root": root }),
            ControlAction::WalletBalance { address, asset } => {
                json!({ "address": address, "asset": asset_to_wire(asset) })
            }
            // Split from the balance arm because this read is PAGED. The two page fields are
            // OMITTED when unset rather than sent as null, so the node applies the CONTRACT's
            // default page size -- sending a number this CLI invented would make `dign wallet
            // coins` page differently from every other client for no reason a user asked for.
            ControlAction::WalletCoins {
                address,
                asset,
                after_coin_id,
                limit,
            } => {
                let mut params = json!({ "address": address, "asset": asset_to_wire(asset) });
                if let Some(after) = after_coin_id {
                    params["after_coin_id"] = json!(after);
                }
                if let Some(limit) = limit {
                    params["limit"] = json!(limit);
                }
                params
            }
            ControlAction::WalletCoinById { coin_id }
            | ControlAction::WalletCoinSpend { coin_id } => json!({ "coin_id": coin_id }),
            // A DIFFERENT field name, on purpose: the contract names the subject
            // `parent_coin_id` so a one-hop answer cannot read as a truncated lineage. Folding it
            // into the arm above would send `coin_id` and the node would refuse it as missing.
            ControlAction::WalletCoinsByParent {
                parent_coin_id,
                after_coin_id,
                limit,
            } => {
                // The two page fields are OMITTED when unset rather than sent as null, so the node
                // applies the CONTRACT's default page size. Sending a number this CLI invented
                // would make `dig-node wallet coins-by-parent` page differently from every other
                // client for no reason a user asked for.
                let mut params = json!({ "parent_coin_id": parent_coin_id });
                if let Some(after) = after_coin_id {
                    params["after_coin_id"] = json!(after);
                }
                if let Some(limit) = limit {
                    params["limit"] = json!(limit);
                }
                params
            }
            ControlAction::WalletArrivals { after_seq, limit } => {
                json!({ "after_seq": after_seq, "limit": limit })
            }
            ControlAction::WalletBroadcast { signed_bundle_hex } => {
                json!({ "signed_bundle_hex": signed_bundle_hex })
            }
            // Without these two arms the keys the user typed are dropped by the `_` fall-through
            // below and the node is asked to follow nothing, which it refuses as a missing
            // `params.public_keys`. The refusal is correct and the command is unusable.
            ControlAction::WalletWatch { public_keys }
            | ControlAction::WalletUnwatch { public_keys } => {
                json!({ "public_keys": public_keys })
            }
            // `ttl_secs` is omitted rather than sent as null when unset, so the node applies its
            // own default instead of being handed a value to reject.
            ControlAction::WalletReservationsReserve { coin_ids, ttl_secs } => match ttl_secs {
                Some(t) => json!({ "coin_ids": coin_ids, "ttl_secs": t }),
                None => json!({ "coin_ids": coin_ids }),
            },
            ControlAction::WalletReservationsRelease { reservation_id } => {
                json!({ "reservation_id": reservation_id })
            }
            ControlAction::ProfilePutBody {
                store_id,
                root,
                body_b64,
            } => json!({ "store_id": store_id, "root": root, "body_b64": body_b64 }),
            ControlAction::ProfileGetBody { store_id, root } => {
                json!({ "store_id": store_id, "root": root })
            }
            ControlAction::UpdaterSetChannel { channel } => json!({ "channel": channel }),
            ControlAction::UpdaterPause { until: Some(u) } => json!({ "until": u }),
            ControlAction::SubsAdd { store_id } | ControlAction::SubsRemove { store_id } => {
                json!({ "store_id": store_id })
            }
            ControlAction::ChiaPeersAdd { ip } => json!({ "ip": ip }),
            ControlAction::ChiaPeersRemove { ip, ban } => json!({ "ip": ip, "ban": ban }),
            _ => json!({}),
        }
    }
}

/// Run a control-parity subcommand: dispatch the mapped `control.*` method over the shared
/// loopback client and render an [`Outcome`] (a concise human summary + the raw `result` for
/// `--json`). Transport / node errors surface as `io::Error` for the differentiated exit code.
pub fn run(config: &Config, action: ControlAction) -> std::io::Result<Outcome> {
    let method = action.method();
    let result = call_control(config, method, action.wire_params())?;
    Ok(Outcome::new(summarize(method, &result), result))
}

/// Every `control.*` method reachable from a `dig-node` CLI verb — the union of the
/// control-parity actions here and the `control.pairing.*` methods `dig-node pair` drives
/// (#280). The drift test asserts this COVERS [`crate::control::CONTROL_METHODS`], so a new
/// node control method cannot ship without a CLI verb.
pub fn cli_covered_control_methods() -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = vec![
        // The control-parity actions (this module).
        ControlAction::Info.method(),
        ControlAction::ConfigGet.method(),
        ControlAction::ConfigSetUpstream { url: String::new() }.method(),
        ControlAction::CacheGet.method(),
        ControlAction::CacheSetCap { bytes: 0 }.method(),
        ControlAction::CacheClear.method(),
        ControlAction::StoresList.method(),
        ControlAction::StoresPin {
            store: String::new(),
        }
        .method(),
        ControlAction::StoresUnpin {
            store: String::new(),
        }
        .method(),
        ControlAction::StoresStatus {
            store: String::new(),
        }
        .method(),
        ControlAction::CapsuleFetch {
            store: String::new(),
            root: String::new(),
        }
        .method(),
        ControlAction::SyncStatus.method(),
        ControlAction::SyncTrigger {
            store: String::new(),
        }
        .method(),
        ControlAction::WalletBalance {
            address: String::new(),
            asset: String::new(),
        }
        .method(),
        ControlAction::WalletCoins {
            address: String::new(),
            asset: String::new(),
            after_coin_id: None,
            limit: None,
        }
        .method(),
        ControlAction::WalletCoinById {
            coin_id: String::new(),
        }
        .method(),
        ControlAction::WalletCoinSpend {
            coin_id: String::new(),
        }
        .method(),
        ControlAction::WalletCoinsByParent {
            parent_coin_id: String::new(),
            after_coin_id: None,
            limit: None,
        }
        .method(),
        ControlAction::WalletArrivals {
            after_seq: 0,
            limit: 0,
        }
        .method(),
        ControlAction::WalletPeak.method(),
        ControlAction::WalletSyncStatus.method(),
        ControlAction::WalletBroadcast {
            signed_bundle_hex: String::new(),
        }
        .method(),
        ControlAction::WalletWatch {
            public_keys: Vec::new(),
        }
        .method(),
        ControlAction::WalletUnwatch {
            public_keys: Vec::new(),
        }
        .method(),
        ControlAction::WalletWatched.method(),
        ControlAction::WalletReservationsHeld.method(),
        ControlAction::WalletReservationsReserve {
            coin_ids: Vec::new(),
            ttl_secs: None,
        }
        .method(),
        ControlAction::WalletReservationsRelease {
            reservation_id: String::new(),
        }
        .method(),
        ControlAction::ProfilePutBody {
            store_id: String::new(),
            root: String::new(),
            body_b64: String::new(),
        }
        .method(),
        ControlAction::ProfileGetBody {
            store_id: String::new(),
            root: String::new(),
        }
        .method(),
        ControlAction::UpdaterStatus.method(),
        ControlAction::UpdaterSetChannel {
            channel: String::new(),
        }
        .method(),
        ControlAction::UpdaterPause { until: None }.method(),
        ControlAction::UpdaterResume.method(),
        ControlAction::UpdaterCheckNow.method(),
        ControlAction::SubsList.method(),
        ControlAction::SubsAdd {
            store_id: String::new(),
        }
        .method(),
        ControlAction::SubsRemove {
            store_id: String::new(),
        }
        .method(),
        // `dign chia-peers add|list|remove` drives the trusted-Chia-peer surface
        // (dig_ecosystem#2870).
        ControlAction::ChiaPeersAdd { ip: String::new() }.method(),
        ControlAction::ChiaPeersList.method(),
        // `dign collateral requirement` and `dign collateral margin [set …]` drive the
        // deterministic mirror-coin collateral surface (dig_ecosystem#3173).
        ControlAction::CollateralRequirement.method(),
        ControlAction::CollateralMarginGet.method(),
        ControlAction::CollateralBuffer.method(),
        ControlAction::CollateralMarginSet { margin_bp: 0 }.method(),
        // `dign mirror bond-states` drives the §25.8 bond surface (dig-node#412).
        ControlAction::MirrorBondStates {
            after: None,
            limit: None,
        }
        .method(),
        ControlAction::ChiaPeersRemove {
            ip: String::new(),
            ban: false,
        }
        .method(),
        // `dig-node peers counts` reports both networks' peer counts (dig_ecosystem#2501); it
        // lives beside the other peer verbs rather than under `wallet`, because only one of the
        // two numbers it reports is the wallet's.
        "control.peerCounts",
        // `dig-node logs level <filter>` drives the live level change (#553).
        "control.log.setLevel",
        // `dig-node peers` drives the live peer status (#559); `dig-node peers connect <peer>` dials
        // a peer into the pool (#929); `dig-node peers ping <peer>` walks the connection ladder
        // (dig_ecosystem#1985).
        "control.peerStatus",
        "control.peers.connect",
        "control.peers.ping",
        // `dign spends list` drives the automated-spend audit record (dig-node#385). It reads the
        // same node-private file through the same `SpendLog`, so the CLI and the control method
        // cannot disagree about what the record says -- which is the property the contract's
        // "only sanctioned reader" rule is protecting, and the reason this is one verb rather than
        // a second parser.
        "control.spends.list",
        // `dig-node pair …` drives the pairing-admin methods (#280).
        "control.pairing.list",
        "control.pairing.approve",
        "control.pairing.revoke",
    ];
    methods.sort_unstable();
    methods.dedup();
    methods
}

/// A concise human summary of a control result. Falls back to compact JSON for a method with
/// no bespoke line, so every subcommand prints SOMETHING readable even without hand-tuning.
fn summarize(method: &str, result: &Value) -> String {
    match method {
        "control.status" => format!(
            "dig-node {} — up {}s · {} hosted store(s) · {} cached capsule(s) · sync {} · {}",
            result["version"].as_str().unwrap_or("?"),
            result["uptime_secs"].as_u64().unwrap_or(0),
            result["hosted_store_count"].as_u64().unwrap_or(0),
            result["cached_capsule_count"].as_u64().unwrap_or(0),
            avail(&result["sync"]["available"]),
            wallet_mtls_clause(&result["wallet_mtls"]),
        ),
        "control.config.get" => format!(
            "addr {} · upstream {} · cache {}",
            result["addr"].as_str().unwrap_or("?"),
            result["upstream"].as_str().unwrap_or("?"),
            result["cache_dir"].as_str().unwrap_or("?"),
        ),
        "control.config.setUpstream" => format!(
            "upstream set to {} (effective on next node start)",
            result["upstream"].as_str().unwrap_or("?"),
        ),
        "control.cache.get" => format!(
            "cache {} / {} bytes used/cap · {}",
            result["used_bytes"].as_u64().unwrap_or(0),
            result["cap_bytes"].as_u64().unwrap_or(0),
            result["dir"].as_str().unwrap_or("?"),
        ),
        "control.cache.setCap" => format!(
            "cache cap set to {} bytes",
            result["cap_bytes"].as_u64().unwrap_or(0),
        ),
        "control.cache.clear" => "cache cleared".to_string(),
        "control.hostedStores.list" => {
            let stores = result["stores"].as_array().map(Vec::len).unwrap_or(0);
            format!("{stores} hosted store(s)")
        }
        "control.sync.status" => format!(
            "§21 sync {} · {}/{} pinned store(s) synced",
            avail(&result["available"]),
            result["pinned_synced"].as_u64().unwrap_or(0),
            result["pinned_total"].as_u64().unwrap_or(0),
        ),
        "control.hostedStores.status" => format!(
            "store {} — {} · {} cached capsule(s) · {} bytes",
            result["store_id"].as_str().unwrap_or("?"),
            pinned(&result["pinned"]),
            result["capsule_count"].as_u64().unwrap_or(0),
            result["total_bytes"].as_u64().unwrap_or(0),
        ),
        // The node ACKNOWLEDGES a start; it does not wait for the transfer. The summary says which
        // of the three outcomes happened and never implies the capsule has landed — a line reading
        // "fetched" for a pull still crossing the network would be the surface lying about what the
        // node did.
        "control.capsule.fetch" => format!(
            "capsule {}:{} — {}",
            result["store"].as_str().unwrap_or("?"),
            result["root"].as_str().unwrap_or("?"),
            match result["status"].as_str().unwrap_or("?") {
                "started" => "pull started (runs in the background)",
                "already_cached" => "already cached; no pull needed",
                "unavailable" => "no pull possible: this node has no P2P capsule warmer",
                other => other,
            },
        ),
        "control.hostedStores.pin" => {
            format!("pinned {}", result["store_id"].as_str().unwrap_or("?"),)
        }
        "control.hostedStores.unpin" => format!(
            "unpinned {} · {} cached capsule(s) evicted",
            result["store_id"].as_str().unwrap_or("?"),
            result["evicted_capsules"].as_u64().unwrap_or(0),
        ),
        "control.listSubscriptions" => {
            let count = result["subscriptions"]
                .as_array()
                .map(Vec::len)
                .unwrap_or_else(|| result["count"].as_u64().unwrap_or(0) as usize);
            format!("{count} subscription(s)")
        }
        // The ADD line carries the cost, because this is the moment a person grants authority and
        // it is the last moment they can decline. The node returns the sentence (`notice`) so the
        // CLI quotes it rather than keeping a second copy that can drift; the fallback exists only
        // for an older node that does not send one, and says the same thing in fewer words.
        // The headline follows the RESULTING trust state, and the node's own `notice` is quoted
        // verbatim rather than paraphrased: adding a banned peer un-bans it WITHOUT granting
        // trust, and a fixed "trusting ..." line would assert a bypass nothing conferred.
        "control.chiaPeers.add" => format!(
            "{} Chia peer {}\n{}",
            // ABSENT means trust WAS granted: a node too old to send the field is one that always
            // granted it, so defaulting to `false` would report a peer as untrusted while the node
            // believes it without corroboration. Only an explicit `false` -- the un-banned-without-
            // trust case a 0.18 node reports -- says the bypass was withheld.
            if result["corroboration_bypassed"].as_bool().unwrap_or(true) {
                "trusting"
            } else {
                "un-banned (NOT trusted)"
            },
            endpoint(&result["ip"], &result["port"]),
            // An older node sends no `notice`. The fallback must still name the cost, or the
            // warning disappears against exactly the nodes least likely to have it documented.
            result["notice"].as_str().unwrap_or(
                "This peer is now TRUSTED: its answers can update this node's wallet replica on \
                 their own, without being agreed by other peers. Add only a node you run yourself."
            ),
        ),
        "control.chiaPeers.list" => summarize_chia_peers(result),
        // MATCHED on the outcome, never on a boolean: "no_such_peer" means the peer the operator
        // meant to un-trust is STILL trusted, and reporting that as success is the failure the
        // enum exists to prevent.
        "control.chiaPeers.remove" if result["outcome"] == "no_such_peer" => format!(
            "NOTHING removed — no Chia peer matches {}. Any peer you meant to un-trust is still \
             trusted; check `dign chia-peers list` for how the address is stored.",
            result["ip"].as_str().unwrap_or("?"),
        ),
        "control.chiaPeers.remove" => format!(
            "no longer trusting Chia peer {}{}",
            result["ip"].as_str().unwrap_or("?"),
            if result["banned"].as_bool().unwrap_or(false) {
                " (banned — discovery cannot re-add it)"
            } else {
                ""
            },
        ),
        "control.subscribe" => format!(
            "subscribed to {}",
            result["store_id"].as_str().unwrap_or("?"),
        ),
        "control.unsubscribe" => format!(
            "unsubscribed from {}",
            result["store_id"].as_str().unwrap_or("?"),
        ),
        "control.wallet.balance" => format!(
            "balance {} · pending {} · {}",
            result["balance"].as_u64().unwrap_or(0),
            result["pending"].as_u64().unwrap_or(0),
            if result["synced"].as_bool().unwrap_or(false) {
                "synced"
            } else {
                "syncing"
            },
        ),
        // `result["coin"]` yields `Null` for a missing key, but indexing the INNER map would
        // panic on one — so every field is read with `get`, and a coin record short of a field
        // prints an honest unknown instead of aborting the CLI.
        "control.wallet.arrivals" => {
            let n = result["arrivals"].as_array().map(Vec::len).unwrap_or(0);
            format!(
                "{n} arrival(s) · cursor {}",
                result["cursor"].as_i64().unwrap_or(0)
            )
        }
        "control.wallet.coinById" => match result["coin"].as_object() {
            None => "no such coin on chain".to_string(),
            Some(coin) => {
                let field = |key: &str| coin.get(key).unwrap_or(&Value::Null).clone();
                format!(
                    "coin {} · {} · created {} · {}",
                    field("coin_id").as_str().unwrap_or("?"),
                    mojos(&field("amount")),
                    height(&field("created_height")),
                    match field("spent_height").as_u64() {
                        Some(h) => format!("spent at {h}"),
                        None => "unspent".to_string(),
                    },
                )
            }
        },
        // Reports the reveal/solution SIZES rather than their hex, which routinely runs to
        // kilobytes: a human summary that scrolls a terminal off its own screen is not a summary.
        // `--json` carries the bytes for anything that needs them.
        "control.wallet.coinSpend" => match result["spend"].as_object() {
            None => "no spend of that coin on chain (unspent, or unknown)".to_string(),
            Some(spend) => {
                let hex_len = |key: &str| spend[key].as_str().unwrap_or_default().len() / 2;
                format!(
                    "spend of {} at height {} · puzzle reveal {} bytes · solution {} bytes",
                    spend["coin"]["coin_id"].as_str().unwrap_or("?"),
                    height(&spend["coin"]["spent_height"]),
                    hex_len("puzzle_reveal"),
                    hex_len("solution"),
                )
            }
        },
        // Says explicitly whether the page is the whole child set, and how to get the rest. A
        // summary that printed only a count would let a truncated page read as a finished hop --
        // the exact misreading `complete` exists to prevent.
        // Says explicitly whether the page is the whole unspent set, and how to get the rest. A
        // summary that printed only a count would let a truncated page read as an address's whole
        // holdings -- which is a person deciding they cannot afford something they can.
        "control.wallet.coins" => {
            let coins = result["coins"].as_array().map(Vec::len).unwrap_or(0);
            format!("{coins} unspent coin(s){}", page_suffix(result))
        }
        "control.wallet.coinsByParent" => {
            let coins = result["coins"].as_array().map(Vec::len).unwrap_or(0);
            format!(
                "{coins} direct child coin(s) — one hop, not a lineage{}",
                page_suffix(result)
            )
        }
        "control.collateral.requirement" => summarize_collateral_requirement(result),
        "control.collateral.buffer" => summarize_collateral_buffer(result),
        "control.mirror.bondStates" => summarize_mirror_bond_states(result),
        // Shown with its real cost, not as a bare setting: a margin is a number of basis points
        // until someone says what it costs to hold.
        "control.collateral.margin.get" | "control.collateral.margin.set" => {
            summarize_margin(result)
        }
        "control.updater.status" => summarize_updater_status(result),
        _ => compact(result),
    }
}

/// Whether a paged answer is the whole set, and how to resume when it is not.
///
/// Shared by both paged coin reads. The dangerous rendering is the one this exists to prevent: a
/// summary that prints only a count lets a TRUNCATED page read as the whole answer, and the two
/// pages are indistinguishable by length whenever the total is a multiple of the page size.
///
/// The third arm is not dead. `complete: null` is the contract's "a node too old to page", and
/// saying so is better than printing nothing — a caller shown a bare count from such a node cannot
/// tell it apart from a node that measured and found the set complete.
fn page_suffix(result: &Value) -> String {
    match (result["complete"].as_bool(), result["cursor"].as_str()) {
        (Some(true), _) => " · complete".to_string(),
        (_, Some(cursor)) => format!(" · MORE remain — resume after {cursor}"),
        _ => " · completeness unknown (a node too old to say)".to_string(),
    }
}

/// `dign mirror bond-states` — one page of this node's mirror bonds, and what they lock.
///
/// Decoded through the contract's own type rather than by reading JSON keys, on the same terms as
/// [`summarize_collateral_requirement`]: a payload this build cannot decode is reported as
/// undecodable, never rendered as a figure.
///
/// An `unknown` answer prints as UNKNOWN with its reason and NO count. "0 bonds" is a definite
/// claim about this node's money, and it is not the claim a node that could not read its chain
/// made — a person shown a zero stops looking, which is the failure the whole call-level unknown
/// exists to prevent.
fn summarize_mirror_bond_states(result: &Value) -> String {
    use dig_node_control_interface::results::{
        MirrorBondState, MirrorBondStatesResult, MirrorBondStatesUnknownReason,
    };

    use crate::collateral::format_dig;

    let answer = match serde_json::from_value::<MirrorBondStatesResult>(result.clone()) {
        Ok(answer) => answer,
        Err(e) => return format!("mirror bonds: unreadable answer from the node ({e})"),
    };

    let (entries, complete, cursor, locked_dig_base_units, epoch) = match answer {
        MirrorBondStatesResult::Unknown { reason } => {
            let (missing, remedy) = match reason {
                MirrorBondStatesUnknownReason::ServedSetUnknown => (
                    "this node cannot enumerate what it serves",
                    "check the capsule cache",
                ),
                MirrorBondStatesUnknownReason::ChainUnreadable => (
                    "this node cannot read the chain",
                    "configure a chain source",
                ),
                MirrorBondStatesUnknownReason::InFlightUnknown => (
                    "this node cannot see its own in-flight creates",
                    "check the automated-spend record",
                ),
                MirrorBondStatesUnknownReason::ProvenanceUnknown => (
                    "this node cannot tell held capsules from relayed ones",
                    "check the capsule cache",
                ),
            };
            return format!("mirror bonds UNKNOWN — {missing} · {remedy}");
        }
        MirrorBondStatesResult::Known {
            entries,
            complete,
            cursor,
            locked_dig_base_units,
            epoch,
        } => (entries, complete, cursor, locked_dig_base_units, epoch),
    };

    // Counted by state, because the counts are what an operator acts on: only `unfunded` is a
    // shortfall, and the other six mean "no coin yet" for reasons that need entirely different
    // responses. A bare row count would flatten them back together.
    let mut bonded = 0usize;
    let mut unfunded = 0usize;
    let mut other = 0usize;
    for entry in &entries {
        match entry.state {
            MirrorBondState::Bonded { .. } => bonded += 1,
            MirrorBondState::Unfunded { .. } => unfunded += 1,
            _ => other += 1,
        }
    }

    // The locked figure is the node's WHOLE-SET total and is labelled as such, so a page is never
    // read as the whole of this operator's locked money.
    let page = format!(
        "epoch {epoch}: {} bond(s) on this page — {bonded} bonded, {unfunded} unfunded, {other} other · {} locked across ALL bonds",
        entries.len(),
        format_dig(locked_dig_base_units),
    );
    match (complete, cursor) {
        (true, _) => format!("{page} · complete"),
        (false, Some(cursor)) => format!(
            "{page} · MORE remain — resume after {}:{}",
            cursor.store_id, cursor.root
        ),
        // A truncated page with no cursor is a node contradicting itself; say so rather than
        // print a resume instruction nobody can follow.
        (false, None) => format!("{page} · MORE remain, but the node handed back no cursor"),
    }
}

/// `dign collateral buffer` — how much $DIG to hold, and whether this operator is short.
///
/// # Why the served-pair count is an OPERAND and not a lookup
///
/// The buffer's first term is the number of `(owner, store, root)` triples THIS NODE serves. No
/// published control method exposes that set: `control.collateral.requirement`'s `stores` and
/// `owners` are NETWORK census figures — the contract says in as many words that neither is a node
/// count — and `control.hostedStores.list` is a list of pinned and cached stores, which is a
/// different set that merely resembles it.
///
/// An earlier version of this command substituted `hostedStores.list`, and that was wrong: a
/// resemblance is not an identity, and the error is invisible because both produce a plausible
/// number. Until `control.collateral.buffer` publishes (dig-node-control-interface#36), the count
/// is supplied by the caller, and its absence is reported as
/// [`BufferUnknownReason::ServedSetUnknown`] rather than guessed. Adoption is then a wiring step:
/// the operand is replaced by the node's own served set, and nothing else here changes.
///
/// The **balance** is an operand for the same reason. This node cannot know which address holds an
/// operator's $DIG, and a balance read of the wrong address returns a confident number about the
/// wrong money.
pub fn collateral_buffer(
    config: &Config,
    pairs_served: Option<u64>,
    spendable_dig_base_units: Option<u64>,
) -> std::io::Result<Outcome> {
    let requirement_json = call_control(
        config,
        ControlAction::CollateralRequirement.method(),
        json!({}),
    )?;
    let margin_json = call_control(
        config,
        ControlAction::CollateralMarginGet.method(),
        json!({}),
    )?;
    buffer_outcome(
        requirement_json,
        margin_json,
        pairs_served,
        spendable_dig_base_units,
    )
}

/// Turn the two control answers into the buffer outcome — everything after the I/O.
///
/// # Why this is separate from [`collateral_buffer`]
///
/// Both guards this function carries are observable ONLY in the string it returns: that an
/// undecodable margin is refused rather than defaulted to zero, and that an operator-supplied root
/// count is marked as such. Left inline behind two `call_control` round trips, neither could be
/// exercised without a listening node, and both duly went unpinned — a round-2 gate reverted them
/// together and the suite stayed green. A defect in what a person reads needs a test that reads it.
fn buffer_outcome(
    requirement_json: Value,
    margin_json: Value,
    pairs_served: Option<u64>,
    spendable_dig_base_units: Option<u64>,
) -> std::io::Result<Outcome> {
    use crate::collateral::buffer_advice;
    use dig_node_control_interface::params::DEFAULT_BUFFER_HORIZON_EPOCHS;

    let requirement: dig_node_control_interface::results::CollateralRequirementResult =
        serde_json::from_value(requirement_json).map_err(std::io::Error::other)?;
    // Decoded typed and REFUSED if undecodable, never defaulted to zero. A zero margin is a
    // legitimate setting, so a missing one substituted for it is indistinguishable from a real
    // answer — and it understates the recommendation by exactly the cushion the operator chose,
    // which is enough to render `BelowRecommendedBuffer` as `Funded`.
    let margin: dig_node_control_interface::results::CollateralMarginResult =
        serde_json::from_value(margin_json).map_err(std::io::Error::other)?;

    let advice = buffer_advice(
        pairs_served,
        &requirement,
        margin.margin_bp,
        spendable_dig_base_units,
        DEFAULT_BUFFER_HORIZON_EPOCHS,
    );
    let result = serde_json::to_value(advice).map_err(std::io::Error::other)?;

    // PROVENANCE. `pairs_served_by_this_node` is named as though the node counted it, and on the
    // node's own answer it did. Here it is whatever the operator typed after `--roots`, and the
    // rendered line is otherwise identical — so an operator's guess would be indistinguishable
    // from a measurement, including in the recommendation derived from it. Marking it makes the
    // named limitation visible where the figure is read rather than only in the help text. The
    // marker goes away when the node serves its own served-set count (dig-node#387).
    let mut human = render_buffer(&advice);
    if pairs_served.is_some() {
        human.push_str(
            "\n  (store-root count supplied by you via `--roots`, not measured by this node)",
        );
    }
    Ok(Outcome::new(human, result))
}

/// Render a buffer answer as the human line, for BOTH the node-computed and the
/// operator-supplied forms.
///
/// One renderer on purpose: two renderings of one money figure is how an operator comes to
/// trust the wrong one.
fn render_buffer(advice: &CollateralBufferResult) -> String {
    use crate::collateral::{buffer_remedy, format_dig, one_epoch_lock};
    let known = match *advice {
        CollateralBufferResult::Unknown { reason } => {
            // Names the missing fact and what would resolve it. Emphatically not a zero: a zero
            // buffer reads as "no buffer needed", which is the reassuring rendering of an unknown.
            return format!(
                "collateral buffer UNKNOWN — {}.\n  Run `dign collateral requirement` to see \
                 what this node does know.",
                buffer_remedy(reason)
            );
        }
        known @ CollateralBufferResult::Known { .. } => known,
    };
    let CollateralBufferResult::Known {
        funding_state,
        recommended_buffer_dig_base_units,
        spendable_dig_base_units,
        pairs_served_by_this_node,
        required_per_store_dig_base_units,
        margin_bp,
        overlap_dig_base_units,
        escalation_headroom_dig_base_units,
        horizon_epochs,
        escalation_ceiling_micros,
        ..
    } = known
    else {
        unreachable!("the unknown arm returned above")
    };
    // Derived rather than carried: the contract publishes the three inputs, so a client and this
    // node compute the same lock instead of trusting a fourth field that could disagree with them.
    let lock = one_epoch_lock(
        pairs_served_by_this_node,
        required_per_store_dig_base_units,
        margin_bp,
    );

    // The working is shown, briefly. A figure nobody can sanity-check is a figure nobody acts on,
    // and the horizon is stated because a buffer without its horizon is a magic number.
    let mut summary = format!(
        "serving {} store root(s) at {} DIG each ({} bp margin)\n  \
         this epoch locks {} DIG · reclaim overlap {} DIG · escalation headroom {} DIG over {} \
         epochs (x{}.{:06} ceiling — a worst case, not a forecast)\n  \
         recommended holding {} DIG",
        pairs_served_by_this_node,
        format_dig(required_per_store_dig_base_units),
        margin_bp,
        format_dig(lock),
        format_dig(overlap_dig_base_units),
        format_dig(escalation_headroom_dig_base_units),
        horizon_epochs,
        escalation_ceiling_micros / 1_000_000,
        escalation_ceiling_micros % 1_000_000,
        format_dig(recommended_buffer_dig_base_units),
    );

    // The number a person acts on goes LAST, where the eye lands, and it is an amount rather than
    // an adjective: "balance low" is not actionable, "add 3.250 DIG" is.
    // Derived, not carried: the contract publishes the recommendation and the balance, so a
    // shortfall field would be a fourth number that could disagree with the two it comes from.
    let short =
        format_dig(recommended_buffer_dig_base_units.saturating_sub(spendable_dig_base_units));
    summary.push_str("\n  ");
    summary.push_str(&match funding_state {
        CollateralFundingState::ShortNow => format!(
            "SHORT NOW — you cannot cover this epoch; store roots are going uncollateralised. \
             Add at least {} DIG now, {short} DIG to reach the recommendation.",
            format_dig(lock.saturating_sub(spendable_dig_base_units)),
        ),
        CollateralFundingState::DangerouslyLow => format!(
            "DANGEROUSLY LOW — this epoch is covered, but a rise at the ceiling would not be. \
             Add {short} DIG to reach the recommendation."
        ),
        // Deliberately unalarming prose: every epoch this state covers IS covered, and it is a
        // readout rather than a shortfall (`CollateralFundingState::is_shortfall`).
        CollateralFundingState::BelowRecommendedBuffer => format!(
            "below the recommended buffer — every epoch is covered, but there is no cushion. \
             Add {short} DIG to reach it."
        ),
        // Zero served roots is NOT the same sentence as "your funding is sufficient", even though
        // the arithmetic agrees: saying "funded" to an operator serving nothing implies their store
        // roots are covered, and they have none.
        CollateralFundingState::Funded if pairs_served_by_this_node == 0 => {
            "no store roots to collateralise — nothing to fund.".to_string()
        }
        CollateralFundingState::Funded => {
            "funded — at or above the recommended buffer.".to_string()
        }
    });

    summary
}

/// A concise human line for `control.collateral.buffer` — the node's OWN answer.
///
/// Shares [`render_buffer`] with the operator-supplied form of `dign collateral buffer`, so the two
/// cannot describe the same figures differently. Two renderings of one money figure is how an
/// operator comes to trust the wrong one.
fn summarize_collateral_buffer(result: &Value) -> String {
    match serde_json::from_value::<CollateralBufferResult>(result.clone()) {
        Ok(answer) => render_buffer(&answer),
        // A payload this build cannot decode is reported as such, never as a figure. Guessing at a
        // partially-understood money answer is worse than saying the node spoke a shape we do not
        // know.
        Err(e) => format!("collateral buffer: unreadable answer from the node ({e})"),
    }
}

/// A concise human line for `control.collateral.requirement`.
///
/// The census inputs travel with the figure on purpose: a surface that can show only the number can
/// say the price moved, while one holding `stores`, `owners`, the multiplier and the handicap can
/// say WHY it moved — the difference between a figure an operator can weigh and one they can only
/// accept.
///
/// The unknown branch prints the REASON, never a zero. Each reason names a different missing fact
/// because the remedies differ: a node that has not censused the epoch needs to run the census,
/// whereas one inside the finality depth only needs to wait.
///
/// # Why this decodes typed instead of guarding on the `state` string
///
/// An earlier version tested `state == "unknown"` positively and let EVERY other payload fall
/// through to a formatter whose fields were each `unwrap_or(0)`. That renders an unrecognised state
/// as a real epoch number beside a fabricated `0.000 DIG per store` — which reads as authoritative
/// rather than degraded, and is the exact money lie the unknown branch exists to prevent. An
/// operator acting on it posts nothing and leaves every store root uncollateralised.
///
/// The trigger is a PLANNED event, not a failure. [`CollateralRequirementResult`] is
/// `#[serde(tag = "state")]`, so a new variant is an ADDITIVE contract change, and `dign` and the
/// node are separately installed binaries — so the next minor would make every already-installed
/// `dign` print it. Decoding typed means an undecodable payload is reported as undecodable, exactly
/// as [`summarize_collateral_buffer`] already does.
fn summarize_collateral_requirement(result: &Value) -> String {
    use dig_node_control_interface::results::{
        CollateralRequirementResult, CollateralUnknownReason,
    };

    let answer = match serde_json::from_value::<CollateralRequirementResult>(result.clone()) {
        Ok(answer) => answer,
        // A payload this build cannot decode is reported as such, never as a figure. Guessing at a
        // partially-understood money answer is worse than saying the node spoke a shape we do not
        // know.
        Err(e) => return format!("collateral requirement: unreadable answer from the node ({e})"),
    };

    let (epoch, protocol_version, required, stores, owners, multiplier, handicap) = match answer {
        CollateralRequirementResult::Unknown { reason } => {
            let (reason, remedy) = match reason {
                CollateralUnknownReason::NotCensused => (
                    "this node has not censused the epoch",
                    "run the census for this epoch",
                ),
                CollateralUnknownReason::BehindFinalityDepth => (
                    "the epoch's census inputs are not final yet",
                    "wait for the chain to settle",
                ),
                CollateralUnknownReason::RecordUnreadable => (
                    "the record for this epoch could not be read",
                    "re-run the census for this epoch",
                ),
                CollateralUnknownReason::NoChainSource => {
                    ("this node cannot see the chain", "configure a chain source")
                }
                // The WALLET, not the census. An operator told their census is broken would go
                // looking at the chain, and the chain is fine.
                CollateralUnknownReason::BalanceUnreadable => (
                    "this node cannot read its own $DIG balance",
                    "check the node's operator wallet",
                ),
            };
            // Emphatically NOT "0 DIG". An absent requirement rendered as a zero cost is the money
            // lie this surface exists to prevent.
            return format!("collateral requirement UNKNOWN — {reason} · {remedy}");
        }
        CollateralRequirementResult::Known {
            epoch,
            protocol_version,
            required_per_store_dig_base_units,
            stores,
            owners,
            multiplier_micros,
            handicap_dig_base_units,
        } => (
            epoch,
            protocol_version,
            required_per_store_dig_base_units,
            stores,
            owners,
            multiplier_micros,
            handicap_dig_base_units,
        ),
    };

    let dig = crate::collateral::format_dig;
    format!(
        "epoch {} (protocol v{}) — {} DIG per store, before any safety margin\n  \
         from {} advertisement(s) across {} collateralised owner(s) · multiplier {}.{:06}x · \
         handicap {} DIG",
        epoch,
        protocol_version,
        dig(required),
        stores,
        owners,
        multiplier / 1_000_000,
        multiplier % 1_000_000,
        dig(handicap),
    )
}

/// A concise human line for the local safety margin, WITH what it costs.
///
/// A margin shown alone is a number of basis points and nothing more. Shown beside the per-store
/// amount it adds, it is a decision an operator can make — which is the whole point of exposing the
/// setting rather than just storing it.
///
/// Decoded typed for the same reason as [`summarize_collateral_requirement`]: zero is a legitimate
/// margin, so an absent one substituted for it reads as a deliberate choice the operator did not
/// make — and this line is what they check after `margin set`, which makes it the one place a
/// silently-defaulted zero would be believed.
fn summarize_margin(result: &Value) -> String {
    let bp = match serde_json::from_value::<
        dig_node_control_interface::results::CollateralMarginResult,
    >(result.clone())
    {
        Ok(margin) => margin.margin_bp,
        Err(e) => return format!("safety margin: unreadable answer from the node ({e})"),
    };
    let preset = match bp {
        b if b == dig_mirror_collateral::SAFETY_MARGIN_BP_TIGHT => " (tight)",
        b if b == dig_mirror_collateral::SAFETY_MARGIN_BP_DEFAULT => " (default)",
        b if b == dig_mirror_collateral::SAFETY_MARGIN_BP_GENEROUS => " (generous)",
        _ => "",
    };
    // Percent is shown for readability only; the STORED unit is basis points, and a 1 bp margin
    // must still read as 0.01% rather than rounding away to zero.
    format!(
        "safety margin {bp} bp{preset} = +{}.{:02}% over the per-store requirement",
        bp / 100,
        bp % 100,
    )
}

/// A concise human line for the auto-update beacon status (`control.updater.status`). The rich
/// beacon report is a deeply-nested object; a first-time operator wants the at-a-glance line
/// (installed? which version + channel, paused-or-running, the last outcome), with the full detail
/// still available via `--json`.
fn summarize_updater_status(result: &Value) -> String {
    if !result["installed"].as_bool().unwrap_or(false) {
        return "auto-update beacon not installed".to_string();
    }
    let status = &result["status"];
    let paused = if status["paused"].as_bool().unwrap_or(false) {
        "paused"
    } else {
        "running"
    };
    format!(
        "updater installed · v{} · channel {} · {}{}",
        status["version"].as_str().unwrap_or("?"),
        status["channel"].as_str().unwrap_or("?"),
        paused,
        match status["last_outcome"].as_str() {
            Some(o) => format!(" · last outcome {o}"),
            None => String::new(),
        },
    )
}

/// The `chia-peers list` human view: one line per peer, trusted ones marked.
///
/// The count of TRUSTED peers is stated separately from the total because those are the only ones
/// that can move the replica on their own word — a bare total would hide the number that actually
/// matters. An empty list says so in words rather than printing nothing, which reads as a failure.
fn summarize_chia_peers(result: &Value) -> String {
    let peers = match result["peers"].as_array() {
        Some(peers) if !peers.is_empty() => peers,
        _ => {
            return "no Chia peers tracked yet — `dign chia-peers add <ip>` trusts one by hand"
                .to_string()
        }
    };
    let trusted = peers
        .iter()
        .filter(|p| p["user_managed"].as_bool().unwrap_or(false))
        .count();
    let banned = peers
        .iter()
        .filter(|p| p["banned"].as_bool().unwrap_or(false))
        .count();
    let mut out = format!(
        "{} Chia peer(s) · {trusted} trusted (believed without corroboration) · {banned} banned",
        peers.len(),
    );
    for p in peers {
        out.push_str(&format!(
            "\n  {} · peak {} · {}",
            endpoint(&p["ip"], &p["port"]),
            // A peer nobody has polled reads as "unobserved", never as height 0. Printing 0 would
            // show every such peer stalled at genesis, and this line is the operator's only signal
            // that a peer they trust WITHOUT corroboration has gone stale.
            match p["peak_height"].as_u64() {
                Some(h) => h.to_string(),
                None => "unobserved".to_string(),
            },
            if p["banned"].as_bool().unwrap_or(false) {
                "BANNED (excluded; `remove --no-ban` clears it, granting no trust)"
            } else if p["user_managed"].as_bool().unwrap_or(false) {
                "trusted (you added it)"
            } else {
                "discovered (must be corroborated)"
            },
        ));
    }
    out
}

/// A peer endpoint for a human line, joined by the CONTRACT's
/// [`dig_node_control_interface::params::chia_peer_endpoint`] rather than by pasting a colon
/// between two fields.
///
/// Concatenating is wrong for every IPv6 literal: `::1` and `8444` pasted together read as
/// `::1:8444`, which is itself a valid IPv6 address naming a DIFFERENT host — so the line would not
/// merely look odd, it would identify the wrong peer, and the mistake survives validation because
/// the result is well-formed. DIG is IPv6-first (§5.2), so this is the common case rather than an
/// edge one. The join is the contract's single sanctioned one, not a local reimplementation of the
/// same rule, so the two cannot drift.
///
/// An address the node sent that does not parse is shown VERBATIM with the port named in words,
/// never re-punctuated into something that looks canonical: a CLI that tidied an unparseable
/// address would assert a shape the node never claimed.
fn endpoint(ip: &Value, port: &Value) -> String {
    let text = ip.as_str().unwrap_or("?");
    let port = u16::try_from(port.as_u64().unwrap_or(0)).unwrap_or(0);
    if text.parse::<std::net::IpAddr>().is_ok() {
        dig_node_control_interface::params::chia_peer_endpoint(text, port)
    } else {
        format!("{text} (port {port})")
    }
}

/// The `dign info` clause for the Sage-parity wallet mTLS listener (dig-node#260).
///
/// The listener's bind is best-effort, and a LOST bind used to be invisible from every
/// surface — so an operator whose parity client could not connect had nothing to read.
/// The unavailable case therefore names the contested port and says the wallet is still
/// reachable, because the failure is a lost port, never a broken wallet.
fn wallet_mtls_clause(v: &Value) -> String {
    let port = v["port"].as_u64();
    match (v["state"].as_str(), port) {
        (Some("listening"), Some(port)) => format!("wallet mTLS :{port}"),
        (Some("unavailable"), Some(port)) => format!(
            "wallet mTLS UNAVAILABLE (port {port} held by another process; wallet still served \
             over the loopback HTTP surface)"
        ),
        (Some("not_started"), _) => "wallet mTLS not started".to_string(),
        // An older node, or a state this build does not know: say so rather than guess a
        // listener is healthy.
        _ => "wallet mTLS state unknown".to_string(),
    }
}

/// "available" / "unavailable" for a boolean sync/availability flag.
fn avail(v: &Value) -> &'static str {
    if v.as_bool().unwrap_or(false) {
        "available"
    } else {
        "unavailable"
    }
}

/// A coin amount for a human line: `N mojos`, or `amount unknown` when the field is missing or is
/// not a number.
///
/// Never `0 mojos` on a miss: a zero amount is a real, readable claim about a coin, so printing one
/// for an unreadable field states a fact the CLI does not have.
fn mojos(v: &Value) -> String {
    match v.as_u64() {
        Some(a) => format!("{a} mojos"),
        None => "amount unknown".to_string(),
    }
}

/// A block height for a human line: the number, or `pending` for a null.
///
/// `null` means the coin is known only from the mempool — NOT height zero, which every block is
/// trivially above.
fn height(v: &Value) -> String {
    match v.as_u64() {
        Some(h) => h.to_string(),
        None => "pending".to_string(),
    }
}

/// "pinned" / "not pinned" for a store's boolean pin flag.
fn pinned(v: &Value) -> &'static str {
    if v.as_bool().unwrap_or(false) {
        "pinned"
    } else {
        "not pinned"
    }
}

/// Compact single-line JSON for results without a bespoke summary (the pin/unpin/sync-trigger/
/// updater/subscription results, whose shape is small and self-describing).
fn compact(result: &Value) -> String {
    serde_json::to_string(result).unwrap_or_else(|_| "{}".to_string())
}

/// `dign collateral history` — the epochs this node has recorded, and how it came by each.
///
/// Read from the record file directly rather than over a control call, like `dign spends`: the
/// store is this node's own state on this node's own disk, and an operator diagnosing a node that
/// will not start is exactly the person who most needs to read it.
///
/// # Provenance is shown, never summarised away
///
/// A bootstrap record, a censused one and one adopted from a sample of untrusted peers are three
/// different claims about how much this node knows, and the recommendation an operator funds is
/// derived from whichever it holds. Rendering them identically would present the weakest with the
/// authority of the strongest.
pub fn collateral_history(epoch: Option<u64>) -> std::io::Result<Outcome> {
    use crate::collateral::{EpochRecordStore, StoredEpoch};

    let store = EpochRecordStore::in_state_dir();

    // A single epoch goes through `get`, which distinguishes "never recorded" from "recorded and
    // unreadable". The listing cannot make that distinction and does not pretend to.
    if let Some(epoch) = epoch {
        let (human, result) = match store.get(epoch) {
            StoredEpoch::Found(record) => (render_record(&record), serde_json::to_value(*record)?),
            StoredEpoch::Absent => (
                format!(
                    "epoch {epoch}: NOT RECORDED — this node has not censused it and has not \
                     adopted it from peers."
                ),
                json!({ "epoch": epoch, "record": Value::Null, "reason": "not_recorded" }),
            ),
            StoredEpoch::Unreadable => (
                format!(
                    "epoch {epoch}: RECORDED BUT UNREADABLE — the line for this epoch in {} could \
                     not be parsed. The figures are lost, not absent.",
                    store.path().display()
                ),
                json!({ "epoch": epoch, "record": Value::Null, "reason": "record_unreadable" }),
            ),
        };
        return Ok(Outcome::new(human, result));
    }

    let records = store.records()?;
    let human = if records.is_empty() {
        format!(
            "no collateral epochs recorded yet ({}).",
            store.path().display()
        )
    } else {
        let mut lines = Vec::with_capacity(records.len() + 1);
        lines.push(format!("{} epoch(s) recorded:", records.len()));
        lines.extend(records.iter().map(render_record));
        lines.join("\n")
    };
    let result = json!({
        "path": store.path().display().to_string(),
        "records": records
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?,
    });
    Ok(Outcome::new(human, result))
}

/// One recorded epoch, as a single operator-readable line.
fn render_record(record: &crate::collateral::StoredRecord) -> String {
    use crate::collateral::{format_dig, RecordProvenance};

    let provenance = match record.provenance {
        RecordProvenance::Bootstrap => "genesis (derived from nothing)".to_string(),
        RecordProvenance::Censused => "censused by this node".to_string(),
        RecordProvenance::AdoptedFromPeers { agreed, sampled } => {
            format!("adopted from peers ({agreed} of {sampled} agreed, each re-derived here)")
        }
    };
    // An absent census height is stated as absent. A "0" here would read as a real block.
    let height = match record.census_height {
        Some(height) => format!("census height {height}"),
        None => "no census (epoch 1 is derived from nothing)".to_string(),
    };
    format!(
        "  epoch {} · {} DIG per store · v{} rules · {} advertisement(s) across {} \
         collateralised owner(s) · multiplier {}.{:06}x · {} · {}",
        record.record.epoch,
        format_dig(record.record.required_per_store_dig_base_units),
        record.record.protocol_version.0,
        record.record.census.stores,
        record.record.census.owners,
        record.record.multiplier_micros / 1_000_000,
        record.record.multiplier_micros % 1_000_000,
        height,
        provenance,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::CONTROL_METHODS;

    /// The requirement summary MUST NOT render an absent figure as a number.
    ///
    /// This is the rendering half of the money-lie rule: the wire is already honest (an `unknown`
    /// answer carries no figure at all), and this asserts the human line does not invent one on the
    /// way out. Each reason must also carry ITS OWN remedy, because a node that has not censused
    /// needs to run the census while one inside the finality depth only needs to wait — one shared
    /// sentence for both is unactionable.
    #[test]
    fn an_unknown_requirement_renders_a_reason_and_never_a_figure() {
        let cases = [
            ("not_censused", "censused"),
            ("behind_finality_depth", "final"),
            ("record_unreadable", "could not be read"),
            ("no_chain_source", "chain"),
        ];
        let mut remedies = std::collections::BTreeSet::new();
        for (reason, needle) in cases {
            let line = summarize_collateral_requirement(&json!({
                "state": "unknown",
                "reason": reason,
            }));
            assert!(line.contains("UNKNOWN"), "{reason}: {line}");
            assert!(line.contains(needle), "{reason}: {line}");
            // No amount of DIG anywhere. "0.000" would read as "no collateral required", and
            // under-posting costs the operator that epoch's rewards.
            assert!(
                !line.contains("0.000"),
                "{reason} rendered a zero cost: {line}"
            );
            assert!(
                !line.contains("per store"),
                "{reason} implied a figure: {line}"
            );
            remedies.insert(line.rsplit('·').next().unwrap_or("").trim().to_string());
        }
        // Four distinct remedies, not one sentence reused four times.
        assert_eq!(remedies.len(), 4, "the remedies collapsed: {remedies:?}");
    }

    #[test]
    fn a_known_requirement_shows_the_census_inputs_behind_the_figure() {
        let line = summarize_collateral_requirement(&json!({
            "state": "known",
            "epoch": 104,
            "protocol_version": 1,
            "required_per_store_dig_base_units": 3_780u64,
            "stores": 17,
            "owners": 820,
            "multiplier_micros": 900_000u64,
            "handicap_dig_base_units": 720u64,
        }));
        // The figure, at three decimals -- 3_780 base units is 3.780 DIG, not 3.78 and not 3780.
        assert!(line.contains("3.780 DIG per store"), "{line}");
        // And it says the figure is PRE-margin, so nobody reads it as what they must hold.
        assert!(line.contains("before any safety margin"), "{line}");
        // The inputs, so a person can say WHY the price moved rather than only that it did.
        assert!(line.contains("104"), "{line}");
        assert!(line.contains("17 advertisement"), "{line}");
        // "collateralised owner(s)", never "nodes" -- one owner hash may back many nodes.
        assert!(line.contains("820 collateralised owner"), "{line}");
        assert!(
            !line.contains("node(s)"),
            "owners must not be rendered as nodes: {line}"
        );
        assert!(line.contains("0.900000x"), "{line}");
        assert!(line.contains("0.720 DIG"), "{line}");
    }

    /// A well-formed `known` requirement, for the buffer fixtures below.
    fn known_requirement_json() -> Value {
        json!({
            "state": "known",
            "epoch": 104,
            "protocol_version": 1,
            "required_per_store_dig_base_units": 3_780u64,
            "stores": 17,
            "owners": 820,
            "multiplier_micros": 1_000_000u64,
            "handicap_dig_base_units": 0u64,
        })
    }

    /// The recommendation the buffer reaches for `margin_bp`, read off the machine result.
    fn recommendation_at(margin_bp: u64) -> u64 {
        let outcome = buffer_outcome(
            known_requirement_json(),
            json!({ "margin_bp": margin_bp }),
            Some(3),
            Some(u64::MAX / 2),
        )
        .expect("a well-formed pair decodes");
        outcome.result["recommended_buffer_dig_base_units"]
            .as_u64()
            .expect("a known answer carries its recommendation")
    }

    /// An undecodable margin must ABORT the buffer, never be substituted with zero.
    ///
    /// # Why this asserts the FLIP and not merely an error
    ///
    /// The nearest wrong implementation is `unwrap_or(0)`, and it fails in the dangerous
    /// direction: it understates the recommendation by exactly the cushion the operator chose, so
    /// a node that is `BelowRecommendedBuffer` reads as `Funded` and nobody adds the $DIG. An
    /// `is_err()` assertion alone would pin the refusal while saying nothing about why it matters —
    /// and would still pass if the cushion had quietly stopped affecting the figure.
    ///
    /// So the balance is pinned at the ZERO-margin recommendation: the exact point at which the
    /// two implementations disagree about the funding state. A margin of zero calls that funded; a
    /// real 500 bp margin does not. The fixture is calibrated at run time from the machine result
    /// rather than from a hard-coded figure, so it cannot drift out of the band it is testing.
    #[test]
    fn an_undecodable_margin_aborts_the_buffer_rather_than_becoming_a_zero_cushion() {
        let at_zero = recommendation_at(0);
        let at_500 = recommendation_at(500);
        // The cushion is real money, and it is the money the defaulted-to-zero path would drop.
        assert!(
            at_500 > at_zero,
            "a 500 bp margin must recommend more than none: {at_500} vs {at_zero}"
        );

        // Held at exactly the zero-margin recommendation: funded only if the cushion is ignored.
        let human = |margin_bp: u64| {
            buffer_outcome(
                known_requirement_json(),
                json!({ "margin_bp": margin_bp }),
                Some(3),
                Some(at_zero),
            )
            .expect("a well-formed pair decodes")
            .summary
        };
        let fabricated = human(0);
        let truthful = human(500);
        assert!(
            fabricated.contains("funded"),
            "the zero-margin reading should be the reassuring one: {fabricated}"
        );
        assert!(
            !truthful.contains("funded — at or above"),
            "a real 500 bp margin must not read as funded at the zero-margin figure: {truthful}"
        );
        assert!(
            truthful.contains("Add "),
            "the truthful reading must state an amount to add: {truthful}"
        );

        // And the defect itself: an undecodable margin produces NO reading at all.
        for (label, margin) in [
            ("empty object", json!({})),
            ("wrong type", json!({ "margin_bp": "500" })),
            ("misspelled field", json!({ "marginBp": 500 })),
        ] {
            let outcome = buffer_outcome(known_requirement_json(), margin, Some(3), Some(at_zero));
            assert!(
                outcome.is_err(),
                "{label} produced a buffer reading from an unknown margin: {:?}",
                outcome.map(|o| o.summary)
            );
        }
    }

    /// An operand-supplied root count is MARKED, and the shared renderer does not mark anything.
    ///
    /// # Why the second assertion is the load-bearing one
    ///
    /// This is a PLACEMENT, not an outcome: the marker is correct only when it sits on the operand
    /// path. Put it inside [`render_buffer`] instead — the obvious "simplification", since that is
    /// where the line is built — and the node's OWN measured answer starts claiming the operator
    /// supplied a count they never typed, which is the same confusion inverted. Asserting only
    /// that the operand path carries the marker would pass under that mislocation.
    ///
    /// So the second actor is the shared renderer, given the SAME advice: it must stay silent.
    #[test]
    fn an_operand_supplied_root_count_is_marked_and_only_on_the_operand_path() {
        const MARKER: &str = "supplied by you via `--roots`";

        let operand = buffer_outcome(
            known_requirement_json(),
            json!({ "margin_bp": 100 }),
            Some(3),
            Some(u64::MAX / 2),
        )
        .expect("a well-formed pair decodes")
        .summary;
        assert!(
            operand.contains(MARKER),
            "an operand-supplied count must say so where the figure is read: {operand}"
        );
        assert!(
            operand.contains("not measured by this node"),
            "the marker must say what it is NOT, not merely name the flag: {operand}"
        );

        // The same advice through the shared renderer — the node's own measured answer. Silent.
        let requirement: dig_node_control_interface::results::CollateralRequirementResult =
            serde_json::from_value(known_requirement_json()).expect("fixture decodes");
        let advice = crate::collateral::buffer_advice(
            Some(3),
            &requirement,
            100,
            Some(u64::MAX / 2),
            dig_node_control_interface::params::DEFAULT_BUFFER_HORIZON_EPOCHS,
        );
        let measured = render_buffer(&advice);
        assert!(
            !measured.contains(MARKER),
            "the node's own measured count must not claim an operator supplied it: {measured}"
        );
        // The control: both really are describing the same three roots, so the difference above
        // is the marker and not two unrelated answers.
        assert!(measured.contains("serving 3 store root(s)"), "{measured}");
        assert!(operand.contains("serving 3 store root(s)"), "{operand}");
    }

    /// A payload this build cannot decode must render as UNREADABLE — never as a figure, and never
    /// as the `unknown` branch either.
    ///
    /// # What each fixture distinguishes
    ///
    /// The nearest wrong implementation is the one this replaced: guard positively on
    /// `state == "unknown"`, and let everything else fall through to a formatter of
    /// `unwrap_or(0)`s. It renders a REAL epoch number beside a fabricated `0.000 DIG per store`,
    /// which reads as authoritative rather than degraded.
    ///
    /// So the fixtures carry `epoch: 104` — the SAME epoch as the truthful control above — and the
    /// assertions forbid it appearing. A renderer that leaked any real field through would print
    /// `104` and fail here; asserting only the absence of `0.000` would not catch a formatter that
    /// happened to be given a non-zero requirement.
    ///
    /// The `known`-with-a-missing-field case is the one that separates a typed decode from a
    /// hybrid that matches the state string and then falls back per field: the state token is
    /// perfectly valid there, and only a decode of the whole variant refuses it.
    ///
    /// This matters because the trigger is a PLANNED event: `CollateralRequirementResult` is
    /// `#[serde(tag = "state")]`, so a new variant is additive, and `dign` ships separately from
    /// the node — the next minor would put an unrecognised state in front of every installed CLI.
    #[test]
    fn an_undecodable_requirement_renders_unreadable_and_never_a_figure() {
        let cases = [
            // A state this build has never heard of — the additive-variant case.
            (
                "unrecognised state",
                json!({ "state": "suspended", "epoch": 104 }),
            ),
            // No state tag at all.
            ("empty object", json!({})),
            // A VALID state token whose payload is short a required field. A positive guard on the
            // string cannot tell this from a complete answer.
            (
                "known missing owners",
                json!({
                    "state": "known",
                    "epoch": 104,
                    "protocol_version": 1,
                    "required_per_store_dig_base_units": 3_780u64,
                    "stores": 17,
                    "multiplier_micros": 900_000u64,
                    "handicap_dig_base_units": 720u64,
                }),
            ),
            // An unknown whose REASON this build does not recognise: the reason taxonomy is
            // additive too, and a reason rendered as an empty remedy is its own small lie.
            (
                "unrecognised reason",
                json!({ "state": "unknown", "reason": "awaiting_peer_quorum" }),
            ),
        ];

        for (label, payload) in cases {
            let line = summarize_collateral_requirement(&payload);
            assert!(
                line.contains("unreadable answer from the node"),
                "{label} was not reported as unreadable: {line}"
            );
            // Not a figure, at any value.
            assert!(
                !line.contains("per store"),
                "{label} rendered a per-store figure: {line}"
            );
            assert!(
                !line.contains("0.000"),
                "{label} rendered a zero cost: {line}"
            );
            // Not a real field leaked from the payload. `104` is the live epoch in the truthful
            // control above, so its presence here means the formatter ran.
            assert!(
                !line.contains("104"),
                "{label} leaked a real field into a degraded line: {line}"
            );
            // And not misreported as the node having NAMED a missing fact, which would send the
            // operator to run a census that would not help.
            assert!(
                !line.contains("UNKNOWN"),
                "{label} borrowed the unknown branch: {line}"
            );
        }
    }

    /// An undecodable margin must not render as `0 bp`.
    ///
    /// Zero is a LEGITIMATE margin, which is what makes the old `unwrap_or(0)` dangerous here:
    /// unlike an absent requirement, an absent margin substituted for zero is indistinguishable
    /// from a real answer, and this line is what an operator reads back after `margin set` to
    /// confirm the setting took. The `250` fixture is the distinguishing one — a renderer that
    /// leaked the payload through would still find no `margin_bp`, so the fixture instead proves
    /// the ADJACENT well-formed value renders, keeping a truthful control beside the refusal.
    #[test]
    fn an_undecodable_margin_renders_unreadable_and_never_zero_bp() {
        for (label, payload) in [
            ("empty object", json!({})),
            ("wrong type", json!({ "margin_bp": "250" })),
            ("negative", json!({ "margin_bp": -1 })),
            ("misspelled field", json!({ "marginBp": 250 })),
        ] {
            let line = summarize_margin(&payload);
            assert!(
                line.contains("unreadable answer from the node"),
                "{label} was not reported as unreadable: {line}"
            );
            assert!(
                !line.contains("0 bp"),
                "{label} rendered a fabricated zero margin: {line}"
            );
            assert!(
                !line.contains('%'),
                "{label} rendered a percentage from an unknown: {line}"
            );
        }
        // The truthful control: the same shape, well-formed, still renders its real value.
        assert!(summarize_margin(&json!({ "margin_bp": 250 })).contains("250 bp"));
        // And a genuine zero margin is still reportable as itself.
        let zero = summarize_margin(&json!({ "margin_bp": 0 }));
        assert!(zero.contains("0 bp"), "{zero}");
        assert!(
            !zero.contains("unreadable"),
            "a real zero margin must not be reported as unreadable: {zero}"
        );
    }

    #[test]
    fn the_margin_line_names_its_preset_and_keeps_sub_percent_values() {
        // A 1 bp margin is 0.01%, and rounding it to whole percent would erase a legal choice
        // entirely -- the value would read as no margin at all.
        assert!(summarize_margin(&json!({ "margin_bp": 1 })).contains("+0.01%"));
        assert!(summarize_margin(&json!({ "margin_bp": 1 })).contains("(tight)"));
        assert!(summarize_margin(&json!({ "margin_bp": 100 })).contains("+1.00%"));
        assert!(summarize_margin(&json!({ "margin_bp": 100 })).contains("(default)"));
        assert!(summarize_margin(&json!({ "margin_bp": 500 })).contains("+5.00%"));
        assert!(summarize_margin(&json!({ "margin_bp": 500 })).contains("(generous)"));
        // A value that is nobody's preset is shown plainly rather than mislabelled as the nearest.
        let odd = summarize_margin(&json!({ "margin_bp": 250 }));
        assert!(odd.contains("250 bp"), "{odd}");
        assert!(odd.contains("+2.50%"), "{odd}");
        assert!(
            !odd.contains('('),
            "an unnamed margin must not borrow a preset name: {odd}"
        );
    }

    #[test]
    fn every_action_maps_to_a_control_method() {
        // A representative of each variant → its method is a real `control.*` name.
        for m in cli_covered_control_methods() {
            assert!(m.starts_with("control."), "{m} is not a control method");
        }
    }

    /// PARITY GATE (#426): every `control.*` method the node resolves MUST have a `dig-node`
    /// CLI verb, so the CLI never silently falls behind the WS surface the extension drives.
    /// A new node control method with no CLI verb fails HERE.
    #[test]
    fn cli_covers_every_node_control_method() {
        let covered = cli_covered_control_methods();
        let missing: Vec<&str> = CONTROL_METHODS
            .iter()
            .copied()
            .filter(|m| !covered.contains(m))
            .collect();
        assert!(
            missing.is_empty(),
            "these node control methods have NO CLI verb (add one in control_cli.rs): {missing:?}"
        );
    }

    #[test]
    fn params_carry_the_expected_fields() {
        assert_eq!(
            ControlAction::CacheSetCap { bytes: 123 }.wire_params(),
            json!({ "cap_bytes": 123 })
        );
        assert_eq!(
            ControlAction::StoresPin {
                store: "abc".into()
            }
            .wire_params(),
            json!({ "store": "abc" })
        );
        assert_eq!(
            ControlAction::UpdaterPause { until: Some(99) }.wire_params(),
            json!({ "until": 99 })
        );
        // Enrolment carries the keys the user typed. Measured against a running node before this
        // arm existed: the `_` fall-through sent `{}`, the node answered "requires
        // params.public_keys", and `dign wallet watch <key>` could not follow anything at all.
        assert_eq!(
            ControlAction::WalletWatch {
                public_keys: vec!["aa".into(), "bb".into()],
            }
            .wire_params(),
            json!({ "public_keys": ["aa", "bb"] })
        );
        assert_eq!(
            ControlAction::WalletUnwatch {
                public_keys: vec!["cc".into()],
            }
            .wire_params(),
            json!({ "public_keys": ["cc"] })
        );
        // A pause with no deadline sends an empty object (indefinite pause).
        assert_eq!(
            ControlAction::UpdaterPause { until: None }.wire_params(),
            json!({})
        );
        assert_eq!(
            ControlAction::SubsAdd {
                store_id: "s".into()
            }
            .wire_params(),
            json!({ "store_id": "s" })
        );
    }

    /// **Adding a trusted Chia peer TELLS the person what it costs, on the add line itself.**
    ///
    /// The cost is the whole point of the ticket: a `user_managed` peer reaches
    /// `PeerTrust::Operator` and may move the wallet replica with no quorum at all. A summary that
    /// only confirmed the address would be a surface hiding a cost it imposes.
    ///
    /// The fixture supplies the node's OWN `notice`, because that is the path a current node takes
    /// and a test that only exercised the fallback would leave the quoting path unproven.
    #[test]
    fn adding_a_trusted_chia_peer_states_the_corroboration_bypass() {
        let s = summarize(
            "control.chiaPeers.add",
            &json!({
                "added": true,
                "ip": "203.0.113.7",
                "port": 8444,
                "corroboration_bypassed": true,
                "notice": "This peer is now TRUSTED: its answers can update this node's wallet replica on their own, without being agreed by other peers.",
            }),
        );
        assert!(s.contains("203.0.113.7"), "the address must be echoed: {s}");
        assert!(
            s.contains("203.0.113.7:8444"),
            "the endpoint must be echoed: {s}"
        );
        assert!(s.contains("TRUSTED"), "the grant must be named: {s}");
        assert!(
            s.contains("without being agreed by other peers"),
            "the corroboration bypass must be stated: {s}"
        );
    }

    /// An OLDER node sends no `notice`. The fallback must still name the cost — otherwise the
    /// warning silently disappears against exactly the nodes least likely to have it documented.
    #[test]
    fn the_add_line_still_warns_when_the_node_sends_no_notice() {
        let s = summarize(
            "control.chiaPeers.add",
            &json!({ "added": true, "ip": "203.0.113.7", "port": 8444 }),
        );
        assert!(s.contains("TRUSTED"), "{s}");
        assert!(s.contains("without being agreed by other peers"), "{s}");
    }

    /// **The add line follows the RESULTING trust state, and quotes the node's own words (#254).**
    ///
    /// The fixture varies ONE field — `corroboration_bypassed` — across two otherwise-identical
    /// results, and the un-banned case is the real one: an upsert clears the ban and leaves the
    /// trusted flag alone, so the peer ends up UNTRUSTED while the call succeeds. A renderer with a
    /// fixed "trusting ..." headline passes the granted case and fails here, which is the point;
    /// asserting only the granted case would pin a coincidence.
    #[test]
    fn the_add_line_does_not_claim_a_bypass_the_node_withheld() {
        let granted = summarize(
            "control.chiaPeers.add",
            &json!({ "added": true, "ip": "203.0.113.7", "port": 8444,
                     "corroboration_bypassed": true, "notice": "NOTICE-GRANTED" }),
        );
        assert!(granted.contains("trusting"), "{granted}");
        assert!(
            granted.contains("NOTICE-GRANTED"),
            "the node's own sentence must be quoted verbatim: {granted}"
        );

        let withheld = summarize(
            "control.chiaPeers.add",
            &json!({ "added": true, "ip": "203.0.113.7", "port": 8444,
                     "corroboration_bypassed": false, "notice": "NOTICE-WITHHELD" }),
        );
        assert!(
            withheld.contains("NOT trusted"),
            "an un-banned-without-trust result must not read as a grant: {withheld}"
        );
        assert!(withheld.contains("NOTICE-WITHHELD"), "{withheld}");
        assert!(
            !withheld.contains("NOTICE-GRANTED"),
            "the two cases must be distinguishable: {withheld}"
        );
    }

    /// An ABSENT `corroboration_bypassed` means the bypass WAS granted, not that it was withheld.
    ///
    /// Only a node too old to send the field omits it, and such a node always granted trust.
    /// Defaulting to `false` would report a peer as untrusted while the node believes it without
    /// corroboration — understating authority the operator actually conferred.
    #[test]
    fn an_absent_bypass_flag_reads_as_granted_not_withheld() {
        let s = summarize(
            "control.chiaPeers.add",
            &json!({ "added": true, "ip": "203.0.113.7", "port": 8444 }),
        );
        assert!(s.contains("trusting"), "{s}");
        assert!(!s.contains("NOT trusted"), "{s}");
    }

    /// **The remove line reports a miss as having removed NOTHING (#254 item 2).**
    ///
    /// Both outcomes in one test, because the property is relational: a renderer that printed the
    /// success line unconditionally passes the `removed` case and fails here. `remove` is the only
    /// way to un-trust a peer believed without corroboration, so a miss rendered as success leaves
    /// an operator believing they revoked custody-grade trust they still grant.
    #[test]
    fn the_remove_line_reports_a_miss_as_a_failure_to_act() {
        let hit = summarize(
            "control.chiaPeers.remove",
            &json!({ "outcome": "removed", "ip": "203.0.113.7", "banned": false }),
        );
        assert!(hit.contains("no longer trusting"), "{hit}");

        let miss = summarize(
            "control.chiaPeers.remove",
            &json!({ "outcome": "no_such_peer", "ip": "198.51.100.4", "banned": false }),
        );
        assert!(
            miss.contains("NOTHING removed") && miss.contains("still"),
            "a miss must say nothing was un-trusted: {miss}"
        );
        assert!(
            !miss.contains("no longer trusting"),
            "a miss must NOT read as a successful un-trust: {miss}"
        );
    }

    /// **A banned peer is listed and labelled, and an unpolled peak reads as unobserved (#254).**
    #[test]
    fn the_chia_peer_list_shows_banned_rows_and_never_prints_a_fabricated_peak() {
        let s = summarize(
            "control.chiaPeers.list",
            &json!({ "peers": [
                { "ip": "203.0.113.7", "port": 8444, "peak_height": null,
                  "user_managed": true, "banned": false },
                { "ip": "198.51.100.4", "port": 8444, "peak_height": null,
                  "user_managed": false, "banned": true },
            ] }),
        );
        assert!(s.contains("1 banned"), "the ban count must be stated: {s}");
        assert!(s.contains("BANNED"), "the banned row must be labelled: {s}");
        assert!(
            s.contains("unobserved"),
            "an unpolled peak must not print as a height: {s}"
        );
        assert!(
            !s.contains("peak 0"),
            "printing 0 would read as a trusted peer stalled at genesis: {s}"
        );
    }

    /// An IPv6 endpoint is BRACKETED, because `::1` + `8444` pasted together is a DIFFERENT
    /// valid address rather than a malformed string a parser would reject (#254 item 8).
    #[test]
    fn an_ipv6_peer_endpoint_is_bracketed_not_concatenated() {
        let s = summarize(
            "control.chiaPeers.list",
            &json!({ "peers": [
                { "ip": "::1", "port": 8444, "peak_height": null,
                  "user_managed": true, "banned": false },
            ] }),
        );
        assert!(s.contains("[::1]:8444"), "{s}");
        assert!(!s.contains("::1:8444\n") && !s.ends_with("::1:8444"), "{s}");
    }

    /// **The list distinguishes the trusted peers from the discovered ones, and counts them.**
    ///
    /// The fixture carries ONE of each. A list of only-trusted peers would pass a test that merely
    /// looked for the word "trusted" while a renderer that labelled everything trusted stayed
    /// undetected — so the discovered peer is the control that makes the label load-bearing.
    #[test]
    fn the_chia_peer_list_separates_trusted_peers_from_discovered_ones() {
        let s = summarize(
            "control.chiaPeers.list",
            &json!({ "peers": [
                { "ip": "203.0.113.7", "port": 8444, "peak_height": 100, "user_managed": true },
                { "ip": "198.51.100.4", "port": 8444, "peak_height": 99, "user_managed": false },
            ] }),
        );
        assert!(s.contains("2 Chia peer(s)"), "{s}");
        assert!(
            s.contains("1 trusted"),
            "the trusted COUNT is the one that matters: {s}"
        );
        assert!(s.contains("203.0.113.7"), "{s}");
        assert!(s.contains("trusted (you added it)"), "{s}");
        assert!(
            s.contains("discovered (must be corroborated)"),
            "a discovered peer must NOT read as trusted: {s}"
        );
    }

    /// **An IPv6 peer renders as a real socket address, not two fields pasted together.**
    ///
    /// `::1` and `8444` concatenated read as `::1:8444`, which is a VALID IPv6 address naming a
    /// different host — so the wrong form does not look broken, it looks fine and identifies the
    /// wrong peer. DIG is IPv6-first (§5.2). The v4 peer beside it is the control: it must NOT
    /// acquire brackets, or the "fix" would just be a different misrendering.
    #[test]
    fn an_ipv6_chia_peer_is_bracketed_and_an_ipv4_one_is_not() {
        let s = summarize(
            "control.chiaPeers.list",
            &json!({ "peers": [
                { "ip": "::1", "port": 8444, "peak_height": 1, "user_managed": true },
                { "ip": "203.0.113.7", "port": 8444, "peak_height": 1, "user_managed": false },
            ] }),
        );
        assert!(
            s.contains("[::1]:8444"),
            "an IPv6 peer must be bracketed: {s}"
        );
        assert!(
            !s.contains(" ::1:8444"),
            "the ambiguous form must not appear: {s}"
        );
        assert!(
            s.contains("203.0.113.7:8444"),
            "IPv4 must stay unbracketed: {s}"
        );
    }

    /// An address the node sent that does not parse is shown verbatim, with the port in words
    /// rather than re-punctuated into a shape the node never claimed.
    #[test]
    fn an_unparseable_peer_address_is_not_tidied_into_a_socket_address() {
        let s = summarize(
            "control.chiaPeers.list",
            &json!({ "peers": [
                { "ip": "not-an-ip", "port": 8444, "peak_height": 0, "user_managed": true },
            ] }),
        );
        assert!(s.contains("not-an-ip (port 8444)"), "{s}");
        assert!(!s.contains("not-an-ip:8444"), "{s}");
    }

    /// An empty list SAYS it is empty and names the verb that fills it. Printing nothing reads as
    /// a broken command.
    #[test]
    fn an_empty_chia_peer_list_explains_itself() {
        let s = summarize("control.chiaPeers.list", &json!({ "peers": [] }));
        assert!(s.contains("no Chia peers tracked"), "{s}");
        assert!(s.contains("chia-peers add"), "{s}");
    }

    /// Removal reports the ban distinctly, because forgetting and banning differ in whether
    /// discovery can bring the peer back.
    #[test]
    fn removing_a_trusted_chia_peer_distinguishes_forgetting_from_banning() {
        let forgotten = summarize(
            "control.chiaPeers.remove",
            &json!({ "removed": true, "ip": "203.0.113.7", "banned": false }),
        );
        assert!(forgotten.contains("no longer trusting"), "{forgotten}");
        assert!(!forgotten.contains("banned"), "{forgotten}");

        let banned = summarize(
            "control.chiaPeers.remove",
            &json!({ "removed": true, "ip": "203.0.113.7", "banned": true }),
        );
        assert!(banned.contains("banned"), "{banned}");
        assert!(banned.contains("discovery cannot re-add it"), "{banned}");
    }

    /// The three verbs send the params the node requires. Without these arms the `_`
    /// fall-through sends `{}` and every command is refused for a missing `params.ip`.
    #[test]
    fn the_chia_peer_verbs_carry_their_params() {
        assert_eq!(
            ControlAction::ChiaPeersAdd {
                ip: "203.0.113.7".into()
            }
            .wire_params(),
            json!({ "ip": "203.0.113.7" })
        );
        assert_eq!(
            ControlAction::ChiaPeersRemove {
                ip: "203.0.113.7".into(),
                ban: true
            }
            .wire_params(),
            json!({ "ip": "203.0.113.7", "ban": true })
        );
        assert_eq!(ControlAction::ChiaPeersList.wire_params(), json!({}));
    }

    #[test]
    fn status_summary_reads_the_key_fields() {
        let s = summarize(
            "control.status",
            &json!({
                "version": "0.37.0",
                "uptime_secs": 42,
                "hosted_store_count": 3,
                "cached_capsule_count": 7,
                "sync": { "available": true },
            }),
        );
        assert!(s.contains("0.37.0"));
        assert!(s.contains("42s"));
        assert!(s.contains("3 hosted"));
        assert!(s.contains("sync available"));
    }

    /// REGRESSION (#1851): `control.wallet.balance` emits `balance`/`pending` as JSON NUMBERS
    /// (not strings). The summary line MUST render the actual numeric values — a prior version
    /// read them with `.as_str()`, which always misses on a JSON number and silently prints `?`
    /// for both fields regardless of the real balance.
    #[test]
    fn wallet_balance_summary_renders_numeric_fields() {
        let s = summarize(
            "control.wallet.balance",
            &json!({ "balance": 12345, "pending": 6, "synced": true, "peak_height": 42 }),
        );
        assert!(s.contains("12345"), "got: {s}");
        assert!(s.contains('6'), "got: {s}");
        assert!(!s.contains('?'), "must not fall back to `?`: {s}");
        assert!(s.contains("synced"), "got: {s}");
    }

    /// REGRESSION (dig-node#260): a wallet mTLS listener that LOST its port must be
    /// visible in `dign info`, naming the port, and must be distinguishable from a healthy
    /// one. The listening case is asserted alongside as the control — a clause that says
    /// "unavailable" unconditionally would pass the first assertion on its own.
    #[test]
    fn info_summary_reports_a_lost_wallet_mtls_port() {
        let lost = summarize(
            "control.status",
            &json!({
                "version": "0.128.0",
                "sync": { "available": true },
                "wallet_mtls": { "state": "unavailable", "port": 9776, "reason": "in use" },
            }),
        );
        assert!(lost.contains("UNAVAILABLE"), "got: {lost}");
        assert!(lost.contains("9776"), "the contested port: {lost}");

        let healthy = summarize(
            "control.status",
            &json!({
                "version": "0.128.0",
                "sync": { "available": true },
                "wallet_mtls": { "state": "listening", "port": 9776 },
            }),
        );
        assert!(!healthy.contains("UNAVAILABLE"), "got: {healthy}");
        assert!(healthy.contains("wallet mTLS :9776"), "got: {healthy}");
    }

    #[test]
    fn unknown_method_summary_falls_back_to_compact_json() {
        // A method with no bespoke line still prints SOMETHING readable (compact JSON).
        let s = summarize("control.some.unmapped", &json!({ "foo": "bar" }));
        assert_eq!(s, "{\"foo\":\"bar\"}");
    }

    /// REGRESSION (#836 single-node walk): the walked read/list/pin control commands MUST render a
    /// concise human line in the default (non-`--json`) mode, never a raw JSON dump. Each of these
    /// used to fall through to `compact()` and print a `{...}` blob — jarring for a first-time
    /// operator walking the CLI. The bar: a readable summary that does NOT start with `{`.
    #[test]
    fn walked_read_commands_render_human_summaries_not_raw_json() {
        let cases = [
            (
                "control.updater.status",
                json!({ "installed": true, "status": { "version": "0.14.0", "channel": "stable", "paused": false, "last_outcome": "applied" } }),
                vec!["0.14.0", "stable"],
            ),
            (
                "control.listSubscriptions",
                json!({ "subscriptions": ["a".repeat(64)], "count": 1 }),
                vec!["1 subscription"],
            ),
            (
                "control.subscribe",
                json!({ "subscribed": true, "added": true, "store_id": "abc" }),
                vec!["subscribed", "abc"],
            ),
            (
                "control.unsubscribe",
                json!({ "subscribed": false, "removed": true, "store_id": "abc" }),
                vec!["unsubscribed", "abc"],
            ),
            (
                "control.wallet.coinById",
                json!({ "coin": { "coin_id": "ab", "amount": 7, "created_height": 100, "spent_height": 140 }, "source": "fallback" }),
                vec!["ab", "7 mojos", "100", "spent at 140"],
            ),
            (
                "control.hostedStores.status",
                json!({ "store_id": "abc", "pinned": true, "capsule_count": 2, "total_bytes": 99 }),
                vec!["abc", "pinned", "2 cached capsule"],
            ),
            (
                "control.hostedStores.pin",
                json!({ "store_id": "abc", "root": null, "pinned": true }),
                vec!["pinned", "abc"],
            ),
            (
                "control.hostedStores.unpin",
                json!({ "store_id": "abc", "unpinned": true, "evicted_capsules": 3 }),
                vec!["unpinned", "abc", "3"],
            ),
        ];
        for (method, result, needles) in cases {
            let s = summarize(method, &result);
            assert!(
                !s.starts_with('{'),
                "{method} must render a human line, not raw JSON: {s}"
            );
            for needle in needles {
                assert!(
                    s.contains(needle),
                    "{method} summary `{s}` missing `{needle}`"
                );
            }
        }
    }

    /// An unreadable amount must not print as `0 mojos` — a zero is a real claim about a coin, and
    /// a caller reading a funding coin would take it as "this coin holds nothing".
    #[test]
    fn coin_by_id_summary_never_prints_zero_for_an_unreadable_amount() {
        let s = summarize(
            "control.wallet.coinById",
            &json!({ "coin": { "coin_id": "ab", "created_height": 100, "spent_height": null } }),
        );
        assert!(!s.contains("0 mojos"), "got: {s}");
        assert!(s.contains("amount unknown"), "got: {s}");
    }

    #[test]
    fn updater_status_summary_handles_not_installed() {
        let s = summarize("control.updater.status", &json!({ "installed": false }));
        assert!(!s.starts_with('{'));
        assert!(s.contains("not installed"), "got: {s}");
    }
}
