//! Chain-watch + generation gap-fill (dig-node SPEC §14.2 + §14.3) — the node's autonomous sync loop.
//!
//! This implements the autonomous-sync behaviors the SPEC specifies in §14:
//!
//! - **§14.2 chain-watch** — a background loop polls each SUBSCRIBED store's CHIP-0035 singleton (via
//!   the node's injectable [`AnchoredRootResolver`](crate::AnchoredRootResolver)) on an interval, so a
//!   NEW confirmed generation is detected without a client read driving it. The confirmation
//!   semantics are unchanged from the read-path pin: the unspent-singleton tip's root is the
//!   authority, and an unreachable chain / no-confirmed-generation is a no-op that FAILS CLOSED (the
//!   node never gap-fills against a root the chain could not confirm).
//!
//! - **§14.3 generation gap-fill** — when the confirmed tip is a root the node does not hold locally
//!   (`<cache>/modules/<store>/<root>.module` absent), the node is MISSING that generation. It
//!   actively pulls it down (via the injected [`GapFiller`]), verifying against the chain-anchored
//!   root exactly as a read would, then refreshes its DHT provider records so peers find it as a new
//!   holder. This is the *"actively seek other nodes to pull the missing generations"* behavior.
//!
//! The whole loop is built around two small seams so the policy is unit-testable with NO chain and NO
//! network: the resolver (already injected on the [`Node`](crate::Node)) and the [`GapFiller`] trait.
//! [`decide_watch`] is the pure per-store decision; [`WatchDeps`] bundles the seams the loop drives.

use std::sync::Arc;
use std::time::Duration;

use crate::subscription::SubscriptionSet;
use crate::{AnchoredRootResolver, Bytes32};

/// Default interval between chain-watch polls of the subscribed store set. Deliberately modest — a new
/// generation confirms on-chain in tens of seconds to minutes, so a ~30 s poll detects it promptly
/// without hammering coinset. Overridable via `DIG_NODE_WATCH_INTERVAL` (seconds).
pub const DEFAULT_WATCH_INTERVAL_SECS: u64 = 30;

/// The lower bound on the configured watch interval (seconds) — a floor so a mis-set env var can't
/// turn the loop into a coinset flood. One poll per second is already far faster than generations
/// confirm.
pub const MIN_WATCH_INTERVAL_SECS: u64 = 1;

/// Resolve the chain-watch poll interval from the environment (`DIG_NODE_WATCH_INTERVAL`, seconds),
/// floored at [`MIN_WATCH_INTERVAL_SECS`] and defaulting to [`DEFAULT_WATCH_INTERVAL_SECS`].
pub fn watch_interval_from_env() -> Duration {
    let secs = std::env::var("DIG_NODE_WATCH_INTERVAL")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_WATCH_INTERVAL_SECS)
        .max(MIN_WATCH_INTERVAL_SECS);
    Duration::from_secs(secs)
}

/// The action the watcher decides for one subscribed store after resolving its anchored root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchAction {
    /// Nothing to do: the store has no confirmed generation, the chain was unreachable, or the
    /// confirmed tip is already held locally. FAILS CLOSED — an unconfirmable root is never
    /// gap-filled. Carries a short reason for logging/tests.
    Skip(SkipReason),
    /// The confirmed tip is a generation the node does NOT hold — pull it down (verified) for this
    /// `(store_id, root)`.
    GapFill { store_id: [u8; 32], root: Bytes32 },
}

/// Why the watcher decided to [`WatchAction::Skip`] a store this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The chain read failed (`Err`) — never gap-fill against an unconfirmable root.
    ChainError,
    /// The store has no confirmed on-chain generation yet (`Ok(None)`).
    NoConfirmedGeneration,
    /// The confirmed tip is already held locally — nothing to pull.
    AlreadyHeld,
}

/// The pure per-store watch decision (SPEC §14.2 detect → §14.3 gap-fill). Given the store id, its
/// resolved anchored root, and whether the tip's module is already held locally, decide whether to
/// gap-fill. This is the fail-closed gate the read path uses, applied proactively:
///
/// - chain error (`Err`) → [`SkipReason::ChainError`] (never pull an unconfirmable generation);
/// - no confirmed generation (`Ok(None)`) → [`SkipReason::NoConfirmedGeneration`];
/// - tip already held → [`SkipReason::AlreadyHeld`];
/// - tip NOT held → [`WatchAction::GapFill`] for `(store_id, tip)`.
pub fn decide_watch(
    store_id: [u8; 32],
    anchored: &Result<Option<Bytes32>, String>,
    tip_is_held: bool,
) -> WatchAction {
    match anchored {
        Err(_) => WatchAction::Skip(SkipReason::ChainError),
        Ok(None) => WatchAction::Skip(SkipReason::NoConfirmedGeneration),
        Ok(Some(_tip)) if tip_is_held => WatchAction::Skip(SkipReason::AlreadyHeld),
        Ok(Some(tip)) => WatchAction::GapFill {
            store_id,
            root: *tip,
        },
    }
}

/// The gap-fill actuator: pull a missing generation for `(store_id, root)` down from another node,
/// verify it against the chain-anchored root, and land it in the node's cache. Returns `Ok(())` on a
/// verified, cached generation, or `Err` describing the failure (the loop logs + retries next tick).
///
/// Abstracted as a trait so the watch loop is driven with a deterministic mock in tests (no chain, no
/// peers). Production is [`NodeGapFiller`], which delegates to the node's authenticated §21 whole-store
/// sync (`Node::gap_fill_generation`): the whole `.dig` module for the confirmed generation is pulled
/// from the node's upstream (the tier-4 gateway `rpc.dig.net` by default, or a configured node),
/// chain-anchored-root pinned on every serve (§14.4). A failed pull is simply retried on the next tick.
/// (The DHT-located multi-source range engine is the read-miss fetch path; the proactive
/// whole-generation gap-fill here uses the whole-store sync, per the SPEC §14.3 verification invariant.)
#[async_trait::async_trait]
pub trait GapFiller: Send + Sync {
    /// Pull + verify + cache the generation `(store_id, root)`. Idempotent: a call for an
    /// already-held generation is a cheap success.
    async fn gap_fill(&self, store_id: [u8; 32], root: Bytes32) -> Result<(), String>;
}

/// Whether the node holds the module for `(store_id, root)` locally. A thin seam over
/// [`crate::module_exists`] so the loop's "is this generation missing?" check is injectable in tests.
pub trait HeldCheck: Send + Sync {
    /// `true` iff `<cache>/modules/<store>/<root>.module` is present.
    fn is_held(&self, store_id: &[u8; 32], root: &Bytes32) -> bool;
}

/// The seams the chain-watch loop drives: the store set to watch, the trusted-root resolver, the
/// held-module check, and the gap-fill actuator.
pub struct WatchDeps {
    /// The stores to watch this tick (a snapshot; the loop re-reads it each tick so a live
    /// subscribe/unsubscribe takes effect).
    pub subscriptions: Arc<dyn Fn() -> SubscriptionSet + Send + Sync>,
    /// The trusted anchored-root source (the same resolver the read-path pin uses).
    pub resolver: Arc<dyn AnchoredRootResolver>,
    /// Whether a given `(store, root)` module is already held locally.
    pub held: Arc<dyn HeldCheck>,
    /// The gap-fill actuator (pull + verify + cache).
    pub filler: Arc<dyn GapFiller>,
}

/// The result of running ONE watch tick over the current subscription set — how many stores were
/// checked, how many gap-fills were attempted, and how many succeeded. Returned so the loop can log a
/// concise summary and tests can assert the tick's effect without inspecting side channels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickSummary {
    /// Stores examined this tick (the size of the subscription snapshot).
    pub checked: usize,
    /// Gap-fills attempted (stores whose confirmed tip was not held).
    pub attempted: usize,
    /// Gap-fills that pulled + verified + cached successfully.
    pub filled: usize,
}

/// Run ONE chain-watch tick: snapshot the subscription set, and for each subscribed store resolve its
/// anchored root, decide via [`decide_watch`], and (when a generation is missing) drive the
/// [`GapFiller`]. Pure control flow over the injected seams, so a test drives it end-to-end with a
/// mock resolver + filler and asserts the [`TickSummary`].
pub async fn run_tick(deps: &WatchDeps) -> TickSummary {
    let set = (deps.subscriptions)();
    let mut summary = TickSummary {
        checked: set.len(),
        ..Default::default()
    };
    for store_hex in set.stores() {
        let Some(store_id) = parse_store_id(store_hex) else {
            continue; // sanitized on insert, but never trust a hand-edited file
        };
        let anchored = deps.resolver.anchored_root(&store_id).await;
        match decide_watch(store_id, &anchored, false) {
            // Re-check the held flag only when the chain confirmed a tip (avoids a filesystem stat
            // for the common no-generation / chain-error case).
            WatchAction::GapFill { root, .. } => {
                if deps.held.is_held(&store_id, &root) {
                    continue; // already held — no work
                }
                summary.attempted += 1;
                match deps.filler.gap_fill(store_id, root).await {
                    Ok(()) => {
                        summary.filled += 1;
                        tracing::info!(
                            store = %store_hex,
                            root = %root.to_hex(),
                            "chain-watch: gap-filled a new generation"
                        );
                    }
                    Err(e) => tracing::warn!(
                        store = %store_hex,
                        root = %root.to_hex(),
                        error = %e,
                        "chain-watch: gap-fill failed; will retry next tick"
                    ),
                }
            }
            WatchAction::Skip(_) => {}
        }
    }
    summary
}

/// Run the chain-watch loop until cancelled (spawned + aborted by the peer-network bring-up). On each
/// tick it runs [`run_tick`]; between ticks it sleeps `interval`. Never returns on its own.
pub async fn run_loop(deps: WatchDeps, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    // Fire the first tick immediately (a node that just started should reconcile promptly), then on
    // the interval. `MissedTickBehavior::Delay` keeps ticks from bursting if a tick ran long.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let summary = run_tick(&deps).await;
        if summary.attempted > 0 {
            tracing::debug!(
                checked = summary.checked,
                attempted = summary.attempted,
                filled = summary.filled,
                "chain-watch tick"
            );
        }
    }
}

/// Parse a 64-hex store id into 32 bytes (mirrors the read path's `parse_store_id_arg`, but over a
/// bare hex string rather than a params object).
fn parse_store_id(store_hex: &str) -> Option<[u8; 32]> {
    if store_hex.len() != 64 {
        return None;
    }
    let bytes = hex::decode(store_hex).ok()?;
    bytes.try_into().ok()
}

// -- Production seams: the Node-backed held-check + gap-filler --------------------------------------

/// Production [`HeldCheck`]: whether the node holds `(store, root)` under its cache dir. Holds only
/// the cache dir path (not the whole `Node`) so it is trivially `Send + Sync`.
pub struct NodeHeldCheck {
    cache_dir: std::path::PathBuf,
}

impl NodeHeldCheck {
    /// A held-check over the node's cache dir.
    pub fn new(cache_dir: std::path::PathBuf) -> Self {
        NodeHeldCheck { cache_dir }
    }
}

impl HeldCheck for NodeHeldCheck {
    fn is_held(&self, store_id: &[u8; 32], root: &Bytes32) -> bool {
        crate::module_exists(&self.cache_dir, &hex::encode(store_id), &root.to_hex())
    }
}

/// Production [`GapFiller`]: pull + verify + cache a missing generation via the node's
/// [`gap_fill_generation`](crate::Node::gap_fill_generation) (authenticated §21 whole-store sync,
/// chain-anchored-root pinned, then a DHT provider-record refresh so peers find the new holder).
pub struct NodeGapFiller {
    node: Arc<crate::Node>,
}

impl NodeGapFiller {
    /// A gap-filler backed by the node.
    pub fn new(node: Arc<crate::Node>) -> Self {
        NodeGapFiller { node }
    }
}

#[async_trait::async_trait]
impl GapFiller for NodeGapFiller {
    async fn gap_fill(&self, store_id: [u8; 32], root: Bytes32) -> Result<(), String> {
        self.node.gap_fill_generation(store_id, root).await
    }
}

/// Spawn the chain-watch + gap-fill loop for the standalone node (SPEC §14.2 + §14.3). The loop reads
/// the persisted subscription set each tick (so a live subscribe/unsubscribe takes effect), resolves
/// each subscribed store's anchored root via the node's resolver, and gap-fills any confirmed
/// generation it does not hold. Best-effort + fail-closed — a chain-unreachable / no-generation store
/// is skipped, and a failed pull is retried next tick.
///
/// Spawn-and-detach, like the DHT maintenance loop: the task runs for the process lifetime and is
/// reclaimed on process exit (the standalone node runs the peer network once per process). It does
/// not need explicit abort — nothing in-process tears the peer network down and re-brings it up.
pub fn spawn_chain_watch(node: Arc<crate::Node>) {
    let deps = WatchDeps {
        // Re-read the persisted subscription set each tick.
        subscriptions: Arc::new(crate::load_subscriptions),
        resolver: node.anchored_root_resolver_arc(),
        held: Arc::new(NodeHeldCheck::new(node.cache_dir_path().to_path_buf())),
        filler: Arc::new(NodeGapFiller::new(node.clone())),
    };
    let interval = watch_interval_from_env();
    tokio::spawn(async move { run_loop(deps, interval).await });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn store(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn root(n: u8) -> Bytes32 {
        Bytes32([n; 32])
    }

    // -- decide_watch (pure) -------------------------------------------------------------------------

    /// **Proves:** a chain error never triggers a gap-fill (fail-closed §14.2/§14.3).
    #[test]
    fn chain_error_skips() {
        let d = decide_watch(store(1), &Err("coinset 503".into()), false);
        assert_eq!(d, WatchAction::Skip(SkipReason::ChainError));
    }

    /// **Proves:** a store with no confirmed generation is skipped (nothing to pull).
    #[test]
    fn no_generation_skips() {
        let d = decide_watch(store(1), &Ok(None), false);
        assert_eq!(d, WatchAction::Skip(SkipReason::NoConfirmedGeneration));
    }

    /// **Proves:** an already-held tip is skipped (no redundant pull).
    #[test]
    fn held_tip_skips() {
        let d = decide_watch(store(1), &Ok(Some(root(9))), true);
        assert_eq!(d, WatchAction::Skip(SkipReason::AlreadyHeld));
    }

    /// **Proves:** a confirmed tip the node lacks triggers a gap-fill for exactly `(store, tip)`.
    /// **Catches:** a watcher that pulls the wrong root, or fails to detect a missing generation.
    #[test]
    fn missing_tip_gap_fills() {
        let d = decide_watch(store(7), &Ok(Some(root(3))), false);
        assert_eq!(
            d,
            WatchAction::GapFill {
                store_id: store(7),
                root: root(3)
            }
        );
    }

    /// **Proves:** the interval env var is parsed + floored (a bogus/zero value never floods coinset).
    #[test]
    fn interval_floor_and_default() {
        std::env::remove_var("DIG_NODE_WATCH_INTERVAL");
        assert_eq!(
            watch_interval_from_env(),
            Duration::from_secs(DEFAULT_WATCH_INTERVAL_SECS)
        );
        std::env::set_var("DIG_NODE_WATCH_INTERVAL", "0");
        assert_eq!(
            watch_interval_from_env(),
            Duration::from_secs(DEFAULT_WATCH_INTERVAL_SECS),
            "zero → default, not a busy loop"
        );
        std::env::set_var("DIG_NODE_WATCH_INTERVAL", "5");
        assert_eq!(watch_interval_from_env(), Duration::from_secs(5));
        std::env::remove_var("DIG_NODE_WATCH_INTERVAL");
    }

    // -- run_tick (the loop's body, over mock seams) -------------------------------------------------

    /// A resolver returning a fixed outcome per store id (hex), else `Ok(None)`.
    struct MockResolver(std::collections::HashMap<String, Result<Option<Bytes32>, String>>);
    #[async_trait::async_trait]
    impl AnchoredRootResolver for MockResolver {
        async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
            self.0
                .get(&hex::encode(store_id))
                .cloned()
                .unwrap_or(Ok(None))
        }
    }

    /// A held-check backed by an explicit set of `(store, root)` the node "holds".
    struct MockHeld(Vec<([u8; 32], Bytes32)>);
    impl HeldCheck for MockHeld {
        fn is_held(&self, store_id: &[u8; 32], root: &Bytes32) -> bool {
            self.0.iter().any(|(s, r)| s == store_id && r == root)
        }
    }

    /// A gap-filler that records every `(store, root)` it was asked to pull and returns a scripted
    /// per-call result (so a failing pull can be asserted to retry).
    struct RecordingFiller {
        calls: Mutex<Vec<([u8; 32], Bytes32)>>,
        fail: bool,
    }
    #[async_trait::async_trait]
    impl GapFiller for RecordingFiller {
        async fn gap_fill(&self, store_id: [u8; 32], root: Bytes32) -> Result<(), String> {
            self.calls.lock().unwrap().push((store_id, root));
            if self.fail {
                Err("pull failed".into())
            } else {
                Ok(())
            }
        }
    }

    fn deps_for(
        subs: Vec<[u8; 32]>,
        resolver: MockResolver,
        held: MockHeld,
        filler: Arc<RecordingFiller>,
    ) -> WatchDeps {
        let set = {
            let mut s = SubscriptionSet::new();
            for st in subs {
                s.add(&hex::encode(st)).unwrap();
            }
            s
        };
        WatchDeps {
            subscriptions: Arc::new(move || set.clone()),
            resolver: Arc::new(resolver),
            held: Arc::new(held),
            filler,
        }
    }

    /// **Proves:** the tick gap-fills exactly the subscribed stores whose confirmed tip is missing,
    /// leaves held + no-generation + chain-error stores alone, and reports an accurate summary.
    /// **Catches:** a loop that pulls held generations, pulls against an unconfirmable root, or
    /// mis-counts.
    #[tokio::test]
    async fn tick_gap_fills_only_missing_confirmed_generations() {
        let mut outcomes = std::collections::HashMap::new();
        outcomes.insert(hex::encode(store(1)), Ok(Some(root(0x11)))); // missing → fill
        outcomes.insert(hex::encode(store(2)), Ok(Some(root(0x22)))); // held → skip
        outcomes.insert(hex::encode(store(3)), Ok(None)); // no generation → skip
        outcomes.insert(hex::encode(store(4)), Err("chain down".into())); // error → skip
        let resolver = MockResolver(outcomes);
        let held = MockHeld(vec![(store(2), root(0x22))]);
        let filler = Arc::new(RecordingFiller {
            calls: Mutex::new(Vec::new()),
            fail: false,
        });
        let deps = deps_for(
            vec![store(1), store(2), store(3), store(4)],
            resolver,
            held,
            filler.clone(),
        );

        let summary = run_tick(&deps).await;
        assert_eq!(summary.checked, 4);
        assert_eq!(summary.attempted, 1, "only store 1's tip is missing");
        assert_eq!(summary.filled, 1);
        assert_eq!(
            *filler.calls.lock().unwrap(),
            vec![(store(1), root(0x11))],
            "pulled exactly the one missing generation"
        );
    }

    /// **Proves:** a failed gap-fill is counted attempted-but-not-filled, and a SECOND tick retries it
    /// (interruption-retry, SPEC §14.3) — the store stays missing so the watcher keeps trying.
    /// **Catches:** a watcher that gives up after one failure, or double-counts a success.
    #[tokio::test]
    async fn failed_gap_fill_retries_next_tick() {
        let mut outcomes = std::collections::HashMap::new();
        outcomes.insert(hex::encode(store(1)), Ok(Some(root(0x11))));
        let filler = Arc::new(RecordingFiller {
            calls: Mutex::new(Vec::new()),
            fail: true,
        });
        let deps = deps_for(
            vec![store(1)],
            MockResolver(outcomes),
            MockHeld(vec![]), // never becomes held (the pull "fails")
            filler.clone(),
        );

        let t1 = run_tick(&deps).await;
        assert_eq!((t1.attempted, t1.filled), (1, 0), "attempted, not filled");
        let t2 = run_tick(&deps).await;
        assert_eq!((t2.attempted, t2.filled), (1, 0), "retried next tick");
        assert_eq!(filler.calls.lock().unwrap().len(), 2, "pulled twice");
    }

    /// **Proves:** an empty subscription set is a no-op tick (no resolver/filler calls).
    #[tokio::test]
    async fn empty_subscriptions_no_work() {
        let filler = Arc::new(RecordingFiller {
            calls: Mutex::new(Vec::new()),
            fail: false,
        });
        let deps = deps_for(
            vec![],
            MockResolver(Default::default()),
            MockHeld(vec![]),
            filler.clone(),
        );
        let summary = run_tick(&deps).await;
        assert_eq!(summary, TickSummary::default());
        assert!(filler.calls.lock().unwrap().is_empty());
    }

    /// **Proves:** the subscription snapshot is re-read each tick (a store subscribed between ticks is
    /// picked up). Uses a shared counter to swap the returned set on the second call.
    #[tokio::test]
    async fn resubscribes_are_picked_up_each_tick() {
        let mut outcomes = std::collections::HashMap::new();
        outcomes.insert(hex::encode(store(5)), Ok(Some(root(0x55))));
        let filler = Arc::new(RecordingFiller {
            calls: Mutex::new(Vec::new()),
            fail: false,
        });
        let tick_no = Arc::new(AtomicUsize::new(0));
        let subs = {
            let tick_no = tick_no.clone();
            Arc::new(move || {
                let mut s = SubscriptionSet::new();
                // Tick 0: empty. Tick 1+: store 5 subscribed.
                if tick_no.fetch_add(1, Ordering::SeqCst) >= 1 {
                    s.add(&hex::encode(store(5))).unwrap();
                }
                s
            })
        };
        let deps = WatchDeps {
            subscriptions: subs,
            resolver: Arc::new(MockResolver(outcomes)),
            held: Arc::new(MockHeld(vec![])),
            filler: filler.clone(),
        };

        assert_eq!(run_tick(&deps).await.checked, 0, "tick 0: empty");
        let t2 = run_tick(&deps).await;
        assert_eq!(
            (t2.checked, t2.filled),
            (1, 1),
            "tick 1: new subscription filled"
        );
    }
}
