//! dig_ecosystem#3292: `Node::install_funded_distributor_registry` has a real, non-test caller.
//!
//! Before this ticket the installer was `pub(crate)`, so `dig-node-service` -- the crate that
//! owns `state.state_dir` and constructs the real `Node` -- could not call it at all. This file
//! does not compile against the pre-fix source (a `pub(crate)` method is invisible to this
//! integration-test crate, a separate compilation unit), which is this ticket's RED.

use dig_node_core::rewards::funded::{FundedDistributorsRead, NotConfiguredReason};
use dig_node_core::Node;

/// Mirrors `rewards_chain_port_a3.rs`'s `install_reward_chain_port_refuses_a_second_install`
/// shape for the funder-ownership registry: install from a tempdir, once-only, and the read
/// after install is the correct "no record written yet" UNKNOWN -- never a reassuring empty
/// funded set (dig_ecosystem#3285's whole point; #3291's writer, not this ticket, is what would
/// ever populate it).
#[test]
fn install_funded_distributor_registry_installs_a_tempdir_backed_registry_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let registry =
        dig_node_core::rewards::funded::FundedDistributorRegistry::with_state_dir(dir.path());

    // Sanity on the registry itself, independent of `Node`: a fresh state dir with no record
    // file reads `NotConfigured(NoRecordWritten)`, not `FundsNothing` -- the property the
    // installer must not collapse.
    assert_eq!(
        registry.read(),
        FundedDistributorsRead::NotConfigured(NotConfiguredReason::NoRecordWritten),
        "a fresh state dir with no record file must read as UNKNOWN, never a funded set"
    );

    // `Node` exposes no lighter test constructor to an external integration-test crate --
    // `Node::from_env()` is the same constructor `rewards_chain_port_a3.rs`'s own test uses for
    // the identical reason.
    let node = Node::from_env();

    let first_install = node.install_funded_distributor_registry(registry.clone());
    assert!(first_install, "the first install must be accepted");

    let second_install = node.install_funded_distributor_registry(registry);
    assert!(
        !second_install,
        "the second install must be refused, changing nothing"
    );
}

/// The slice of a source file before its own `#[cfg(test)]` module -- i.e. what actually ships.
/// Duplicated from `rewards_chain_port_a3.rs`'s identical helper because this integration test is
/// a separate compilation unit and cannot import a private helper from that file.
fn production_region(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(test_module_start) => &source[..test_module_start],
        None => source,
    }
}

/// The offset of `needle`'s first occurrence in `haystack`, or a panic naming `msg` -- so a
/// deleted call site fails LOUDLY (with a reason) rather than as a silent `None` swallowed by
/// `.unwrap_or`.
fn must_find(haystack: &str, needle: &str, msg: &str) -> usize {
    haystack.find(needle).unwrap_or_else(|| panic!("{msg}"))
}

/// Closes the gap `server_startup_calls_install_funded_distributor_registry_in_production_code`
/// (above) cannot: that test is a pure CONTAINS check, so it is blind to the install call being
/// *moved* rather than deleted. dig_ecosystem#3292 originally shipped with exactly that shape --
/// the call existed (as a `pub(crate)` no-op nobody drove), just not on a path that ran. The
/// mutation this guards is moving the call inside `if config.enable_chain_sync { .. }`: an
/// integration harness (and every test in this crate) runs with `enable_chain_sync: false`
/// specifically so nothing dials the network, so a call gated behind that flag would silently
/// stop running under the harness AND on any deployment that (for whatever future reason) ships
/// with sync disabled -- reintroducing dig_ecosystem#3292 with a passing `contains(..)` test
/// beside it. Ordering position in the source is the only signal available to a black-box,
/// separate-compilation-unit integration test: see this file's module doc below for why a true
/// runtime distinction between "installed" and "never installed" is not reachable from here.
#[test]
fn install_call_precedes_the_enable_chain_sync_gate_in_production_code() {
    let server_source = production_region(include_str!("../src/server.rs"));

    let install_offset = must_find(
        server_source,
        "install_funded_distributor_registry(",
        "server.rs's production startup path must call \
         `Node::install_funded_distributor_registry`, or dig_ecosystem#3292 has regressed \
         (mutation (a): the call was deleted)",
    );
    let chain_sync_gate_offset = must_find(
        server_source,
        "if config.enable_chain_sync {",
        "server.rs no longer spells its chain-sync gate as `if config.enable_chain_sync {` -- \
         update this test's needle to match, it is not itself evidence of a regression",
    );

    assert!(
        install_offset < chain_sync_gate_offset,
        "install_funded_distributor_registry's call site ({install_offset}) is no longer before \
         the `enable_chain_sync` gate ({chain_sync_gate_offset}): it has moved to or past that \
         gate, which means a node/harness running with chain sync disabled would start with NO \
         funder-ownership registry installed -- dig_ecosystem#3292's exact regression shape \
         (mutation (b))"
    );
}

/// Boots the REAL production startup path (`serve_with_shutdown`, the same function `dig-node
/// run` calls) end to end on an ephemeral loopback port, with chain sync disabled (as every
/// harness must -- see [`must_find`]'s caller's doc). Proves the install call site is reachable
/// and executes without panicking or erroring as part of an actual startup, which
/// `install_funded_distributor_registry_installs_a_tempdir_backed_registry_once` (calling the
/// installer directly, never through `serve_with_shutdown`) cannot: that test would still pass if
/// `server.rs` never called the installer at all.
///
/// # Why this test cannot ALSO assert "installed, not merely not-panicking"
///
/// It would if it could. `Node::funded_distributor_registry` / `Node::funded_distributors_read`
/// are `pub(crate)` to `dig-node-core` -- invisible to `dig-node-service` itself, let alone to
/// this separate integration-test compilation unit -- so there is no accessor this test can call.
/// `AppState`'s `node: Arc<Node>` field is private with no getter, and `serve_with_shutdown`
/// returns only `io::Result<()>` once shutdown resolves, so no caller outside `server.rs` ever
/// holds the `Node` `serve_with_shutdown` built.
///
/// The one externally-reachable read, `dig.listRewardDistributors`, does not help either:
/// `dispatch.rs`'s handler matches
/// `FundedDistributorsRead::NotConfigured(_) | PersistedStateCorrupt { .. } | IoFailed { .. }` as
/// ONE wildcarded arm and answers `Half::NotConsulted` for all three, with no `reason` field on
/// the wire. A registry that was never installed reads `NotConfigured(NoStateDirectory)`; one
/// installed against a fresh, empty state dir (exactly what `serve_with_shutdown` produces, since
/// dig_ecosystem#3291's writer does not exist yet) reads `NotConfigured(NoRecordWritten)` -- two
/// DIFFERENT `NotConfiguredReason` variants, genuinely distinguishable at the type level (see
/// `install_funded_distributor_registry_installs_a_tempdir_backed_registry_once`'s assertion on
/// exactly this), but the RPC response for both is byte-for-byte identical
/// `{"funded":{"status":"not_consulted","observed_at":..},"claimable":{..}}`. So today, "installed
/// and empty" and "never installed" are NOT distinguishable from any observer this crate's tests
/// can reach -- not the RPC surface, not the filesystem (the registry writes nothing at
/// construction or install; only a future recorded funding act would), and not a public accessor.
/// Closing that gap needs either a `#[cfg(test)]`-only accessor on `Node`/`AppState` or a `reason`
/// field on the wire response -- both are production-surface changes, out of this ticket's scope
/// (see this file's brief: "do not change production behaviour... stop and ask me first").
///
/// So this test proves reachability-without-panic, and
/// `install_call_precedes_the_enable_chain_sync_gate_in_production_code` (above) supplies the
/// actual mutation-(b) RED signal, via source position rather than a runtime read.
#[tokio::test]
async fn production_startup_reaches_the_install_call_site_without_panicking() {
    // Serializes with every other test in this crate/process that reads the process-global
    // DIG_NODE_CACHE / DIG_NODE_STATE_DIR env vars live (mirrors `tests/server.rs`'s `env_guard`).
    static ENV_LOCK: std::sync::OnceLock<std::sync::Arc<tokio::sync::Mutex<()>>> =
        std::sync::OnceLock::new();
    let lock = ENV_LOCK
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _hold = lock.lock_owned().await;

    let base = tempfile::Builder::new()
        .prefix("dig-node-3292-startup-")
        .tempdir()
        .expect("a scratch dir");
    let cache = base.path().join("cache");
    std::fs::create_dir_all(&cache).expect("create test cache dir");
    std::env::set_var("DIG_NODE_CACHE", &cache);
    std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
    // Isolates the #501 control-token/paired-token state dir -- also where this ticket's
    // registry persists (`state.state_dir`) -- so this test never touches a real machine's
    // state and no concurrent test shares it.
    std::env::set_var("DIG_NODE_STATE_DIR", base.path());
    // Opts out of the §14 peer network bring-up so this stays hermetic (no gossip/DHT/relay
    // reach), mirroring `tests/server.rs`'s dual-listener test.
    std::env::set_var("DIG_PEER_NETWORK", "off");

    let free = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port to learn a free one");
    let port = free.local_addr().expect("local_addr").port();
    drop(free); // release it so serve_with_shutdown can bind the same port

    let config = dig_node_service::Config {
        port,
        dig_local: false,         // skip the privileged :80 attempt entirely
        enable_chain_sync: false, // never dial mainnet from this harness (#2501)
        ..dig_node_service::Config::default()
    };

    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let stop_for_server = stop.clone();
    let server = tokio::spawn(async move {
        dig_node_service::server::serve_with_shutdown(config, async move {
            stop_for_server.notified().await;
        })
        .await
    });

    // Poll /health until the real startup path (including this ticket's install call, which
    // runs before any listener binds) has completed and the server is actually serving.
    let url = format!("http://127.0.0.1:{port}/health");
    let client = reqwest::Client::new();
    let mut served = false;
    for _ in 0..50 {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                served = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
    assert!(
        served,
        "serve_with_shutdown never reached a serving state -- production startup (which includes \
         this ticket's install_funded_distributor_registry call) did not complete cleanly"
    );

    stop.notify_waiters();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    let join_result =
        outcome.expect("serve_with_shutdown must stop within 5s of the shutdown signal");
    let io_result = join_result.expect("the server task must not panic");
    assert!(
        io_result.is_ok(),
        "serve_with_shutdown returned an error: {io_result:?}"
    );
}
