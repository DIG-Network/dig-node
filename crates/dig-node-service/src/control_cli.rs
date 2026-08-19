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
    /// `control.sync.status` — §21 whole-store sync availability + pinned coverage.
    SyncStatus,
    /// `control.sync.trigger` — trigger a §21 sync for one capsule (`storeId:rootHash`).
    SyncTrigger { store: String },
    /// `control.wallet.balance` — the READ-ONLY balance of a public address (XCH or $DIG).
    WalletBalance { address: String, asset: String },
    /// `control.wallet.coins` — the READ-ONLY unspent coins of a public address (XCH or $DIG).
    WalletCoins { address: String, asset: String },
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
            ControlAction::CacheSetCap { bytes } => json!({ "cap_bytes": bytes }),
            ControlAction::StoresPin { store }
            | ControlAction::StoresUnpin { store }
            | ControlAction::StoresStatus { store }
            | ControlAction::SyncTrigger { store } => json!({ "store": store }),
            ControlAction::WalletBalance { address, asset }
            | ControlAction::WalletCoins { address, asset } => {
                json!({ "address": address, "asset": asset_to_wire(asset) })
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
            "dig-node {} — up {}s · {} hosted store(s) · {} cached capsule(s) · sync {}",
            result["version"].as_str().unwrap_or("?"),
            result["uptime_secs"].as_u64().unwrap_or(0),
            result["hosted_store_count"].as_u64().unwrap_or(0),
            result["cached_capsule_count"].as_u64().unwrap_or(0),
            avail(&result["sync"]["available"]),
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
            if result["corroboration_bypassed"].as_bool().unwrap_or(false) {
                "trusting"
            } else {
                "un-banned (NOT trusted)"
            },
            endpoint(&result["ip"], &result["port"]),
            result["notice"].as_str().unwrap_or(
                "This peer's trust state changed; re-run `dign chia-peers list` to see it."
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
        "control.wallet.coinsByParent" => {
            let coins = result["coins"].as_array().map(Vec::len).unwrap_or(0);
            let more = match (result["complete"].as_bool(), result["cursor"].as_str()) {
                (Some(true), _) => " · complete".to_string(),
                (_, Some(cursor)) => format!(" · MORE remain — resume after {cursor}"),
                _ => " · completeness unknown (a node too old to say)".to_string(),
            };
            format!("{coins} direct child coin(s) — one hop, not a lineage{more}")
        }
        "control.updater.status" => summarize_updater_status(result),
        _ => compact(result),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::CONTROL_METHODS;

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
