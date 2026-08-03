//! The passthrough relay guard — what stops a node from relaying to itself (#1997).
//!
//! A dig-node answers what it implements and, if an operator has configured an upstream, relays
//! what it does not. That relay is the only place the node speaks to a host on a caller's behalf,
//! and it has exactly one catastrophic failure mode: an upstream that leads back to this same
//! process. Then one unimplemented method becomes an unbounded request cycle through whatever sits
//! in between — which is precisely what took the public read tier down.
//!
//! # Two detectors, because neither is sufficient alone
//!
//! [`crate::config::is_self_upstream`] catches the *self-evident* shapes offline and instantly: a
//! loopback host on this node's own port, or the `dig.local` alias. It cannot catch a public name
//! that happens to resolve back here.
//!
//! This module catches that second case, and it does so by **observation rather than prediction**.
//! At bring-up the node sends the upstream one ordinary `dig.health` call, tagged with a
//! single-use random id ([`RelayGuard::probe_id`]). If a request carrying *this node's own* probe
//! id ever arrives at this node's dispatcher, the upstream demonstrably leads here, whatever the
//! DNS, CDN, gateway or load balancer in between happens to be. Passthrough is then switched off
//! for the life of the process.
//!
//! Tagging the `id` rather than inventing a marker method or header matters: the probe is a
//! completely ordinary JSON-RPC `dig.health` request, so it survives any intermediary that
//! forwards JSON-RPC faithfully — including one that drops unknown HTTP headers, as the
//! rpc.dig.net gateway does. The evidence travels in the payload because the payload is the only
//! thing guaranteed to be relayed.
//!
//! # Why guessing the probe id buys an attacker nothing worth having
//!
//! The id is 128 bits of OS randomness, fresh per process. Guessing it would let a caller disable
//! *this* node's outbound passthrough — that is, stop it making requests on callers' behalf. It
//! grants no read, no write, and no access to anything the node holds; it only makes the node more
//! self-contained. There is no configuration in which that is the attacker's goal.

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};

/// The prefix every loop-probe id carries, so a probe is recognisable as one in a log or a packet
/// capture rather than looking like an arbitrary client id.
const PROBE_ID_PREFIX: &str = "dig-node-loop-probe:";

/// The method the probe calls. `dig.health` is the right choice because every node answers it
/// LOCALLY (#1997) — so a healthy, non-looping upstream replies immediately and cheaply, and a
/// looping one hands the request straight back to us, which is the whole signal.
const PROBE_METHOD: &str = "dig.health";

/// Whether this node relays unimplemented methods, and to where.
///
/// Held in [`crate::server::AppState`] and shared by every request, so the moment a loop is proven
/// the very next relay decision already sees it.
pub struct RelayGuard {
    /// The configured upstream, or empty for "no upstream — answer locally" (the default, #1997).
    upstream: String,
    /// This process's single-use probe id. Always generated, even with no upstream configured, so
    /// [`Self::is_own_probe`] never has to reason about an absent value.
    probe_id: String,
    /// Cleared for good once a loop is proven. Never set back to `true`: the upstream cannot stop
    /// pointing at us without a config change, and a config change restarts the node.
    relaying: AtomicBool,
}

impl RelayGuard {
    /// Build the guard for a resolved upstream. An empty `upstream` means passthrough is off.
    pub fn new(upstream: &str) -> Self {
        Self {
            upstream: upstream.to_string(),
            probe_id: format!("{PROBE_ID_PREFIX}{}", crate::control::random_hex(16)),
            relaying: AtomicBool::new(!upstream.is_empty()),
        }
    }

    /// The upstream to relay to. Empty when passthrough is off.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// Whether an unimplemented method should be relayed right now.
    ///
    /// `false` means the honest local answer — `-32601 METHOD_NOT_FOUND` — is returned instead,
    /// which is the correct response for a method this node genuinely does not implement.
    pub fn should_relay(&self) -> bool {
        !self.upstream.is_empty() && self.relaying.load(Ordering::Relaxed)
    }

    /// The one-shot probe request sent to the upstream at bring-up.
    pub fn probe_request(&self) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": self.probe_id,
            "method": PROBE_METHOD,
            "params": {},
        })
    }

    /// Whether an inbound request's `id` is the probe THIS process emitted.
    ///
    /// Matched against the full random id, not the prefix: another node's probe reaching us is
    /// ordinary traffic (it means *we* are somebody's upstream, which is fine), and must not
    /// disable our own passthrough.
    pub fn is_own_probe(&self, id: &Value) -> bool {
        id.as_str() == Some(self.probe_id.as_str())
    }

    /// Record that the upstream has been proven to lead back here, and stop relaying.
    ///
    /// Idempotent, and logs only on the transition so a looping upstream under load cannot turn
    /// the discovery into a log flood.
    pub fn disable_after_loop(&self) {
        if self.relaying.swap(false, Ordering::Relaxed) {
            tracing::error!(
                upstream = %self.upstream,
                "upstream relay loop detected: this node's own probe came back to it, so the \
                 configured upstream leads to this node. Passthrough is now DISABLED for this \
                 process; unimplemented methods will answer -32601 locally. Point \
                 DIG_RPC_UPSTREAM at a different node, or unset it."
            );
        }
    }
}

/// Send the bring-up loop probe, if an upstream is configured.
///
/// The RESPONSE is deliberately ignored — and there is nothing useful in it. The proof of a loop is
/// the probe *arriving back at our own dispatcher*, which happens on the inbound path in
/// [`crate::server`], not here. A timeout, a refusal, or a perfectly good health reply are all
/// equally uninformative, so this logs nothing on failure: an unreachable upstream cannot loop, and
/// warning about it would be noise on every node whose upstream is merely offline.
pub async fn probe_upstream_for_loop(http: &reqwest::Client, guard: &RelayGuard) {
    if !guard.should_relay() {
        return;
    }
    let _ = http
        .post(guard.upstream())
        .json(&guard.probe_request())
        .send()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_upstream_means_no_relay() {
        let g = RelayGuard::new("");
        assert!(!g.should_relay());
        assert_eq!(g.upstream(), "");
    }

    /// **Proves:** [`probe_upstream_for_loop`] actually SENDS the probe — the right method, to the
    /// configured upstream, carrying this guard's own single-use id — and sends nothing at all when
    /// no upstream is configured.
    ///
    /// **Catches:** the function having zero coverage. Detection (what happens when a probe comes
    /// BACK) was well tested; emission was tested nowhere, so deleting the send entirely left the
    /// suite green and the §3.4.1 runtime check wired to nothing. That is the failure mode where a
    /// correct guard ships disconnected.
    ///
    /// **Not covered here:** WHERE the caller spawns this. The probe must be fired after the node's
    /// own listeners are bound, since the evidence is the request arriving back at this node's
    /// dispatcher and `probe_upstream_for_loop` swallows transport errors by design. That ordering
    /// lives in `server::serve_with_shutdown`, which the integration harness does not drive (it
    /// builds a router and calls `axum::serve` directly), so it is verified by inspection rather
    /// than by this test. Stated plainly instead of implied to be covered.
    #[tokio::test]
    async fn the_probe_is_actually_sent_to_the_configured_upstream() {
        use std::sync::{Arc, Mutex};

        let seen: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();

        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(req): axum::Json<Value>| {
                let sink = sink.clone();
                async move {
                    sink.lock().unwrap().push(req);
                    axum::Json(json!({ "jsonrpc": "2.0", "id": 1, "result": {} }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let http = reqwest::Client::new();

        // No upstream: nothing is sent. A probe to nowhere would be a pointless outbound request
        // from every default node on the network.
        probe_upstream_for_loop(&http, &RelayGuard::new("")).await;
        assert!(
            seen.lock().unwrap().is_empty(),
            "an unconfigured node probes nobody"
        );

        let guard = RelayGuard::new(&format!("http://{addr}"));
        probe_upstream_for_loop(&http, &guard).await;

        let calls = seen.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "exactly one probe: {calls:?}");
        assert_eq!(calls[0]["method"], json!(PROBE_METHOD), "{calls:?}");
        assert_eq!(
            calls[0]["id"],
            guard.probe_request()["id"],
            "the marker must ride in the JSON-RPC id — an intermediary that forwards bodies can \
             drop unknown headers, which is exactly what the rpc.dig.net gateway does: {calls:?}"
        );
        let id = calls[0]["id"].as_str().unwrap_or_default();
        assert!(id.starts_with(PROBE_ID_PREFIX), "{calls:?}");
        assert_eq!(
            id.trim_start_matches(PROBE_ID_PREFIX).len(),
            32,
            "single-use 16-byte random suffix; a predictable id would let any caller forge the \
             marker and switch a node's passthrough off: {calls:?}"
        );
    }

    #[test]
    fn a_configured_upstream_relays_until_a_loop_is_proven() {
        let g = RelayGuard::new("http://127.0.0.1:9999");
        assert!(g.should_relay());
        g.disable_after_loop();
        assert!(!g.should_relay());
    }

    /// **Proves:** disabling is idempotent, so a looping upstream under load cannot re-trigger the
    /// transition.
    /// **Catches:** a `store(false)` in place of the `swap`, which would log once per relayed
    /// request for as long as the loop persists.
    #[test]
    fn disabling_twice_is_harmless() {
        let g = RelayGuard::new("http://127.0.0.1:9999");
        g.disable_after_loop();
        g.disable_after_loop();
        assert!(!g.should_relay());
    }

    /// **Proves:** the probe is an ordinary `dig.health` call whose id carries the marker — the
    /// shape that survives an intermediary which forwards JSON-RPC but drops HTTP headers.
    /// **Catches:** a redesign onto a custom header or an invented method name, which is exactly
    /// what the rpc.dig.net gateway would strip.
    #[test]
    fn the_probe_is_an_ordinary_health_call_tagged_in_its_id() {
        let g = RelayGuard::new("http://127.0.0.1:9999");
        let req = g.probe_request();
        assert_eq!(req["method"], json!("dig.health"));
        assert_eq!(req["jsonrpc"], json!("2.0"));
        assert!(req["id"].as_str().unwrap().starts_with(PROBE_ID_PREFIX));
        assert!(g.is_own_probe(&req["id"]));
    }

    /// **Proves:** only OUR probe disables OUR relay.
    /// **Catches:** matching on the prefix instead of the full id — which would let any other
    /// node's probe, or a caller who simply knows the prefix, switch our passthrough off.
    #[test]
    fn another_nodes_probe_is_not_ours() {
        let g = RelayGuard::new("http://127.0.0.1:9999");
        assert!(!g.is_own_probe(&json!("dig-node-loop-probe:deadbeef")));
        assert!(!g.is_own_probe(&json!(PROBE_ID_PREFIX)));
        assert!(!g.is_own_probe(&json!(1)));
        assert!(!g.is_own_probe(&Value::Null));
    }

    /// **Proves:** two processes never share a probe id.
    /// **Catches:** a constant or a per-build id, which would make every node in a deployment
    /// disable every other node's passthrough.
    #[test]
    fn each_guard_gets_its_own_probe_id() {
        let a = RelayGuard::new("http://127.0.0.1:9999");
        let b = RelayGuard::new("http://127.0.0.1:9999");
        assert!(!a.is_own_probe(&b.probe_request()["id"]));
    }
}
