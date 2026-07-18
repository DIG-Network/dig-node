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
            ControlAction::UpdaterStatus => "control.updater.status",
            ControlAction::UpdaterSetChannel { .. } => "control.updater.setChannel",
            ControlAction::UpdaterPause { .. } => "control.updater.pause",
            ControlAction::UpdaterResume => "control.updater.resume",
            ControlAction::UpdaterCheckNow => "control.updater.checkNow",
            ControlAction::SubsList => "control.listSubscriptions",
            ControlAction::SubsAdd { .. } => "control.subscribe",
            ControlAction::SubsRemove { .. } => "control.unsubscribe",
        }
    }

    /// The JSON-RPC params for this action (an empty object for the read/no-arg methods).
    fn params(&self) -> Value {
        match self {
            ControlAction::ConfigSetUpstream { url } => json!({ "upstream": url }),
            ControlAction::CacheSetCap { bytes } => json!({ "cap_bytes": bytes }),
            ControlAction::StoresPin { store }
            | ControlAction::StoresUnpin { store }
            | ControlAction::StoresStatus { store }
            | ControlAction::SyncTrigger { store } => json!({ "store": store }),
            ControlAction::UpdaterSetChannel { channel } => json!({ "channel": channel }),
            ControlAction::UpdaterPause { until: Some(u) } => json!({ "until": u }),
            ControlAction::SubsAdd { store_id } | ControlAction::SubsRemove { store_id } => {
                json!({ "store_id": store_id })
            }
            _ => json!({}),
        }
    }
}

/// Run a control-parity subcommand: dispatch the mapped `control.*` method over the shared
/// loopback client and render an [`Outcome`] (a concise human summary + the raw `result` for
/// `--json`). Transport / node errors surface as `io::Error` for the differentiated exit code.
pub fn run(config: &Config, action: ControlAction) -> std::io::Result<Outcome> {
    let method = action.method();
    let result = call_control(config, method, action.params())?;
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
        // `dig-node logs level <filter>` drives the live level change (#553).
        "control.log.setLevel",
        // `dig-node peers` drives the live peer status (#559); `dig-node peers connect <peer>` dials
        // a peer into the pool (#929).
        "control.peerStatus",
        "control.peers.connect",
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
        "control.subscribe" => format!(
            "subscribed to {}",
            result["store_id"].as_str().unwrap_or("?"),
        ),
        "control.unsubscribe" => format!(
            "unsubscribed from {}",
            result["store_id"].as_str().unwrap_or("?"),
        ),
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

/// "available" / "unavailable" for a boolean sync/availability flag.
fn avail(v: &Value) -> &'static str {
    if v.as_bool().unwrap_or(false) {
        "available"
    } else {
        "unavailable"
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
            ControlAction::CacheSetCap { bytes: 123 }.params(),
            json!({ "cap_bytes": 123 })
        );
        assert_eq!(
            ControlAction::StoresPin {
                store: "abc".into()
            }
            .params(),
            json!({ "store": "abc" })
        );
        assert_eq!(
            ControlAction::UpdaterPause { until: Some(99) }.params(),
            json!({ "until": 99 })
        );
        // A pause with no deadline sends an empty object (indefinite pause).
        assert_eq!(
            ControlAction::UpdaterPause { until: None }.params(),
            json!({})
        );
        assert_eq!(
            ControlAction::SubsAdd {
                store_id: "s".into()
            }
            .params(),
            json!({ "store_id": "s" })
        );
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

    #[test]
    fn updater_status_summary_handles_not_installed() {
        let s = summarize("control.updater.status", &json!({ "installed": false }));
        assert!(!s.starts_with('{'));
        assert!(s.contains("not installed"), "got: {s}");
    }
}
