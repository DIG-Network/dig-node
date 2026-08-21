//! The FORWARDED availability ask — turn "who holds this?" into a recursive, hop-by-hop question
//! asked across the connections this node already holds (dig_ecosystem#3128, requirements 2/3/6).
//!
//! # Why this exists
//!
//! A content miss today is answered from ONE source: this node's own DHT lookup. On a partitioned or
//! heavily relayed network the holder may be perfectly reachable — two hops away through peers this
//! node is already connected to — and completely invisible to the DHT walk. The reader then sees a
//! genuine not-found for content that is genuinely available.
//!
//! So on a miss the node also asks each connected pool peer the SAME question it was asked
//! (`dig.getAvailability`), and that peer answers from its own inventory *and* its own miss
//! enrichment — which asks *its* peers. The question propagates; the `providers` propagate back.
//!
//! # It adds no wire surface whatsoever
//!
//! There is no new verb, no new address struct and no new result type. `dig.getAvailability` already
//! returns a `providers` array on a not-held answer, and `params.redirect_depth` already exists as the
//! hop counter every other redirect leg echoes. This module only issues that existing request and
//! parses that existing answer. A peer running an older build answers without `providers`, which reads
//! as "that peer found nobody" — the correct degradation, not an error.
//!
//! # This module is the WIRE. The DECISION lives in `dig_sex::discovery`
//!
//! Whether to forward at all, to which peers, and with how much budget left is decided by
//! [`dig_sex::discovery::decide_forward`], called from
//! [`NodeContent::forwarded_holders`](crate::download::NodeContent) — including the depth bound
//! (`hop_cap`), the breadth bound (`fan_out`) and the refusal on an unreadable budget. This module
//! only issues the request the decision asked for and parses the answer.
//!
//! The one bound that stays HERE is [`MAX_CONCURRENT_FORWARDED_ASKS`], because it is a property of
//! this node's own resources rather than of the protocol: it bounds how many asks are in flight at
//! once, never how many happen in total.
//!
//! # The answers are hearsay, and are treated as such
//!
//! A forwarded provider is a claim, relayed by an untrusted peer, about a third party. It is offered
//! to the requestor as a candidate to DIAL — where a wrong candidate costs one wasted dial and the
//! merkle bind catches it — and it is deliberately appended AFTER this node's own DHT findings, never
//! ahead of them (see [`crate::download::NodeContent::locate_holders`]).

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use dig_dht::{CandidateAddr, ContentId, PeerId};
use dig_download::ProviderRecord;
use serde_json::{json, Value};

/// The whole-node ceiling on forwarded asks in flight at once, across every requestor and every miss.
///
/// The crate's `fan_out` bounds ONE question; this bounds the node. Without it, a burst of admitted
/// misses multiplies fan-out into hundreds of concurrent dials — the amplification the per-requestor
/// buckets cannot see, because each individual requestor stayed inside its budget. A miss that cannot
/// claim a slot simply does not forward, which costs a less-enriched answer and never a stalled
/// request.
///
/// **It bounds CONCURRENCY, not total work.** The nodes one admitted frame recruits
/// ([`RecursionConfig::worst_case_nodes_recruited`](dig_sex::discovery::RecursionConfig::worst_case_nodes_recruited))
/// still happen; they are merely serialized through 32 slots here, and each downstream node has its
/// own independent 32. Reading this as a cap on the aggregate understates the cost of this path.
pub(crate) const MAX_CONCURRENT_FORWARDED_ASKS: usize = 32;

/// Bounds one forwarded ask end to end (dial + stream + answer). A peer that is slow or gone must not
/// hold the inbound request open: the miss answer is enrichment, so a timeout degrades it rather than
/// failing it. Matches the DHT RPC budget, since the shape of the work is the same.
pub(crate) const FORWARDED_ASK_TIMEOUT: Duration = Duration::from_secs(5);

/// Issue one `dig.getAvailability` to one connected peer and report the providers it named.
///
/// A seam, so the merge policy in [`crate::download::NodeContent::locate_holders`] is testable without
/// a network: the production implementation dials over dig-nat, and tests supply an asker that answers
/// from a fixture.
#[async_trait]
pub(crate) trait ForwardedAsk: Send + Sync {
    /// Ask `peer` (reachable at `addrs`) whether it — or anyone it knows — holds `content`, declaring
    /// `next_depth` as the hop budget already consumed.
    ///
    /// Returns the providers the peer named, which may be empty. Never errors: an unreachable or
    /// silent peer is indistinguishable from one that found nobody, and both mean the same thing to
    /// the answer being built.
    async fn ask(
        &self,
        peer: &str,
        addrs: &[SocketAddr],
        content: &ContentId,
        next_depth: u64,
    ) -> Vec<ProviderRecord>;
}

/// The `dig.getAvailability` request body for `content` at hop budget `next_depth` — the SAME shape
/// any other caller sends, built from the same [`content_id_json`](crate::download::content_id_json)
/// item renderer the redirect uses, so the forwarded question is byte-identical to a direct one.
pub(crate) fn forwarded_request(content: &ContentId, next_depth: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "dig.getAvailability",
        "params": {
            "items": [crate::download::content_id_json(content)],
            "redirect_depth": next_depth,
        },
    })
}

/// Parse the `providers` a `dig.getAvailability` response named for `content`, into records keyed to
/// that content.
///
/// Pure, so the wire contract is pinned without a connection. Every malformed part is DROPPED rather
/// than surfaced: this is an untrusted peer's answer, and a partially-parseable one still carries
/// useful candidates. A response with no `providers` — an older peer, or a peer that found nobody —
/// yields an empty vec, which is the honest reading of both.
pub(crate) fn parse_forwarded_providers(
    content: &ContentId,
    response: &Value,
) -> Vec<ProviderRecord> {
    let key = content.to_key();
    response
        .get("result")
        .and_then(|r| r.get("items"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("providers").and_then(Value::as_array))
        .flatten()
        .filter_map(|provider| {
            let peer_hex = provider.get("peer_id").and_then(Value::as_str)?;
            let peer = PeerId::from_hex(peer_hex)?;
            let addresses: Vec<CandidateAddr> = provider
                .get("addresses")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(parse_candidate_addr)
                .collect();
            // A provider with no dialable address is not a candidate — naming it would spend one of
            // the requestor's few redirect slots on something it cannot try.
            if addresses.is_empty() {
                return None;
            }
            // The peer's own expiry is its claim about its own cache and is not verifiable here. These
            // records live only long enough to be merged into one answer, so they are minted live and
            // never stored; `u64::MAX` says "for this answer", exactly as the pool locator does.
            Some(ProviderRecord::new(&key, &peer, addresses, u64::MAX))
        })
        .collect()
}

/// One `{host, port, kind}` address entry — the shipped `dig.getPeers`/DHT shape, so no second address
/// struct enters the ecosystem. An entry missing either required field is dropped.
fn parse_candidate_addr(addr: &Value) -> Option<CandidateAddr> {
    let host = addr.get("host").and_then(Value::as_str)?;
    let port = u16::try_from(addr.get("port").and_then(Value::as_u64)?).ok()?;
    Some(CandidateAddr::direct(host, port))
}

/// The production [`ForwardedAsk`]: dial the peer over the full dig-nat ladder as this node's mTLS
/// identity, write the framed JSON-RPC request, read the framed answer.
///
/// One connection per ask, matching [`NatDhtTransport`](super::dht::NatDhtTransport) — a forwarded ask
/// is the same size and cadence of work as a DHT RPC, and pooling is a transparent optimisation behind
/// this same trait rather than a correctness concern.
pub(crate) struct NatForwardedAsk {
    node: std::sync::Arc<dig_nat::NodeCert>,
    runtime: std::sync::Arc<dig_nat::NatRuntime>,
    network_id: String,
    stun_server: Option<SocketAddr>,
}

impl NatForwardedAsk {
    /// An asker that dials as `node` over the shared full-ladder `runtime`, scoping relay-coordinated
    /// dials to `network_id`. It builds its dial config from the SAME [`full_nat_config`] every other
    /// node leg uses, so a forwarded ask reaches exactly the peers an ordinary fetch reaches rather
    /// than a narrower Direct-only set.
    ///
    /// [`full_nat_config`]: crate::net::full_nat_config
    pub(crate) fn new(
        node: std::sync::Arc<dig_nat::NodeCert>,
        runtime: std::sync::Arc<dig_nat::NatRuntime>,
        network_id: impl Into<String>,
        stun_server: Option<SocketAddr>,
    ) -> Self {
        Self {
            node,
            runtime,
            network_id: network_id.into(),
            stun_server,
        }
    }
}

#[async_trait]
impl ForwardedAsk for NatForwardedAsk {
    async fn ask(
        &self,
        peer: &str,
        addrs: &[SocketAddr],
        content: &ContentId,
        next_depth: u64,
    ) -> Vec<ProviderRecord> {
        let Some(peer_id) = PeerId::from_hex(peer) else {
            return Vec::new();
        };
        if addrs.is_empty() {
            return Vec::new();
        }
        // The full candidate list, not one collapsed address: `with_addrs` sorts it IPv6-first (§5.2)
        // and the fallback ladder needs every family to try.
        let target = dig_nat::PeerTarget::with_addrs(peer_id, addrs.to_vec(), &self.network_id);
        let config = crate::net::full_nat_config(FORWARDED_ASK_TIMEOUT, self.stun_server);
        let request = forwarded_request(content, next_depth);

        let exchange = async {
            let mut conn =
                dig_nat::connect_with_runtime(&target, &self.node, &config, &self.runtime)
                    .await
                    .ok()?;
            let mut stream = conn.open_stream().await.ok()?;
            crate::peer::write_framed(&mut stream, &request)
                .await
                .ok()?;
            crate::peer::read_framed(&mut stream).await.ok()?
        };

        match tokio::time::timeout(FORWARDED_ASK_TIMEOUT, exchange).await {
            Ok(Some(response)) => parse_forwarded_providers(content, &response),
            // A silent, unreachable or timed-out peer found us nobody. Logged at debug because a
            // relayed network makes this the ordinary case, not a fault.
            _ => {
                tracing::debug!(peer = %peer, "forwarded ask: no answer");
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content() -> ContentId {
        ContentId::resource([1; 32], [2; 32], [3; 32])
    }

    fn answer_with(providers: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "items": [{ "available": false, "providers": providers }] },
        })
    }

    /// **Proves:** the forwarded request is the SHIPPED `dig.getAvailability` shape, naming the content
    /// as one item and carrying the hop budget in the SHIPPED `redirect_depth` key.
    ///
    /// **Catches:** a second way to express the budget (a `hops_remaining`, a per-item field), which is
    /// the byte-drift failure this epic already refused once — a peer reading `redirect_depth` would
    /// see depth 0 forever and the hop cap would stop bounding anything.
    #[test]
    fn the_request_is_the_shipped_verb_carrying_the_shipped_budget_field() {
        let request = forwarded_request(&content(), 3);

        assert_eq!(request["method"], "dig.getAvailability");
        assert_eq!(request["params"]["redirect_depth"], json!(3));
        let items = request["params"]["items"].as_array().expect("items array");
        assert_eq!(items.len(), 1, "exactly the one content asked about");
        assert_eq!(items[0]["store_id"], json!(hex::encode([1u8; 32])));
        assert_eq!(items[0]["root"], json!(hex::encode([2u8; 32])));
        assert_eq!(items[0]["retrieval_key"], json!(hex::encode([3u8; 32])));
    }

    /// **Proves:** a well-formed answer's providers are parsed into records keyed to the content asked
    /// about, carrying the addresses the peer named.
    #[test]
    fn a_named_provider_becomes_a_candidate_keyed_to_the_asked_content() {
        let holder = PeerId::from_bytes([7; 32]).to_hex();
        let response = answer_with(json!([{
            "peer_id": holder,
            "addresses": [{ "host": "2001:db8::1", "port": 9444, "kind": "direct" }],
        }]));

        let found = parse_forwarded_providers(&content(), &response);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].provider_peer_id, holder);
        assert_eq!(
            found[0].content_key,
            content().to_key().to_hex(),
            "keyed to what WE asked about, never to anything the answer claims"
        );
        assert_eq!(found[0].addresses[0].host, "2001:db8::1");
        assert_eq!(found[0].addresses[0].port, 9444);
    }

    /// **Proves:** an answer with no `providers` key — an older peer that predates the enrichment, or
    /// one that genuinely found nobody — yields no candidates rather than an error.
    ///
    /// **Catches:** treating a mixed-version peer as a failure. The recursive ask has to degrade to
    /// "that peer found nobody", because any louder reading turns a rolling upgrade into an outage.
    #[test]
    fn an_answer_without_providers_yields_nobody() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "items": [{ "available": false }] },
        });
        assert!(parse_forwarded_providers(&content(), &response).is_empty());
    }

    /// **Proves:** a JSON-RPC error frame — which is what a peer at the hop cap or over its rate limit
    /// returns — yields no candidates and no panic.
    #[test]
    fn an_error_frame_yields_nobody() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32003, "message": "miss lookup rate limit exceeded" },
        });
        assert!(parse_forwarded_providers(&content(), &response).is_empty());
    }

    /// **Proves:** the parser keeps the well-formed providers out of an answer that also contains
    /// malformed ones, rather than discarding the whole answer.
    ///
    /// **Catches:** an all-or-nothing parse, which would let one peer append a single junk entry to
    /// suppress every genuine holder in the same answer — a cheap censorship primitive.
    #[test]
    fn one_malformed_entry_does_not_discard_the_well_formed_ones() {
        let good = PeerId::from_bytes([5; 32]).to_hex();
        let response = answer_with(json!([
            { "peer_id": "not-64-hex", "addresses": [{ "host": "10.0.0.9", "port": 9444 }] },
            { "peer_id": PeerId::from_bytes([6; 32]).to_hex() },
            { "peer_id": good, "addresses": [{ "host": "10.0.0.1", "port": 9444 }] },
        ]));

        let found = parse_forwarded_providers(&content(), &response);

        assert_eq!(found.len(), 1, "only the well-formed entry survives");
        assert_eq!(found[0].provider_peer_id, good);
    }

    /// **Proves:** a provider naming no dialable address is dropped.
    ///
    /// **Catches:** spending one of the requestor's few [`MAX_REDIRECT_PROVIDERS`] slots on a candidate
    /// it cannot try — which a hostile peer would use to evict the real holders from the answer for
    /// free. The fixture pairs the addressless entry with a real one, so the assertion distinguishes
    /// "dropped the useless entry" from "dropped everything".
    ///
    /// [`MAX_REDIRECT_PROVIDERS`]: crate::download::MAX_REDIRECT_PROVIDERS
    #[test]
    fn a_provider_with_no_dialable_address_is_dropped() {
        let real = PeerId::from_bytes([4; 32]).to_hex();
        let response = answer_with(json!([
            { "peer_id": PeerId::from_bytes([3; 32]).to_hex(), "addresses": [] },
            { "peer_id": real, "addresses": [{ "host": "10.0.0.2", "port": 9444 }] },
        ]));

        let found = parse_forwarded_providers(&content(), &response);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].provider_peer_id, real);
    }

    /// **Proves:** an address entry missing `port`, or carrying one outside `u16`, is dropped while its
    /// well-formed siblings on the SAME provider survive.
    #[test]
    fn a_malformed_address_is_dropped_without_losing_its_siblings() {
        let holder = PeerId::from_bytes([8; 32]).to_hex();
        let response = answer_with(json!([{
            "peer_id": holder,
            "addresses": [
                { "host": "10.0.0.3" },
                { "host": "10.0.0.4", "port": 70000 },
                { "host": "10.0.0.5", "port": 9444 },
            ],
        }]));

        let found = parse_forwarded_providers(&content(), &response);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].addresses.len(), 1, "only the well-formed address");
        assert_eq!(found[0].addresses[0].host, "10.0.0.5");
    }
}
