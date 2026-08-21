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

use super::holder_cache::AskId;
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
/// **It bounds CONCURRENCY, not total work.** The 12 nodes one admitted frame recruits (`3 + 3^2`,
/// the sum over hops — NOT `worst_case_nodes_recruited()`, which returns the last hop's leaf count of
/// 9) still happen; they are merely serialized through 32 slots here, and each downstream node has
/// its own independent 32. Reading this as a cap on the aggregate understates the cost of this path.
pub(crate) const MAX_CONCURRENT_FORWARDED_ASKS: usize = 32;

/// Bounds ONE LEAF ask - a peer that will not itself forward - end to end (dial + stream + answer).
/// Matches the DHT RPC budget, since the shape of the work is the same.
///
/// **This is the leaf, not the whole ask.** A peer that WILL forward is doing `fan_out` asks of its
/// own before it can answer, so granting it this same 5s guarantees it times out. The budget an
/// intermediate hop is given is [`ask_budget`], and the arithmetic connecting the two is the subject
/// of that function's docs.
pub(crate) const FORWARDED_ASK_LEAF_TIMEOUT: Duration = Duration::from_secs(5);

/// The ceiling on any forwarded ask's wall-clock budget, applied to BOTH the budget this node derives
/// for itself and the budget a hop hands it on the wire.
///
/// It exists because the wire budget arrives from an untrusted peer (NC-12). Without a clamp, one hop
/// naming a ten-minute budget holds this node's inbound request - and one of its
/// [`MAX_CONCURRENT_FORWARDED_ASKS`] slots - open for ten minutes, an amplification achieved with a
/// single integer. The clamp is applied at ingress in
/// [`HopBudget::from_params`](crate::download::HopBudget::from_params), so no later reader has to
/// remember to apply it.
pub(crate) const MAX_FORWARDED_ASK_BUDGET: Duration = Duration::from_secs(65);

/// The wall-clock budget an ask that may travel `hops_remaining` further hops actually needs, given a
/// breadth of `fan_out`.
///
/// # Why a fixed per-ask timeout makes the recursion depth-1
///
/// A hop with `h` hops left asks up to `fan_out` peers SEQUENTIALLY, each of which needs
/// `ask_budget(h - 1)`. So the work at depth `h` is `leaf + fan_out * work(h - 1)` - it grows with the
/// same exponent the node count does. A parent that grants every child the LEAF timeout is therefore
/// granting a child less time than the work it is asking that child to do, and at the `dig-sex`
/// defaults (`fan_out = 3`, `hop_cap = 2`) the child needs `3 x 5s = 15s` and is given `5s`. It times
/// out under any load at all, and - before dig-node#273 - a timeout was indistinguishable from an
/// empty answer, so the parent reported a confident *not found* for content two hops away.
///
/// This is the time-domain twin of `RecursionConfig::worst_case_nodes_recruited`: the cost of enabling
/// recursion is an exponent, and this states it as a number an operator can read rather than leaving
/// it to be discovered in production. At the defaults it is 65s, which is also why
/// [`MAX_FORWARDED_ASK_BUDGET`] sits exactly there.
pub(crate) fn ask_budget(hops_remaining: u8, fan_out: u8) -> Duration {
    let mut budget = FORWARDED_ASK_LEAF_TIMEOUT;
    for _ in 0..hops_remaining {
        budget = FORWARDED_ASK_LEAF_TIMEOUT
            .saturating_add(budget.saturating_mul(u32::from(fan_out.max(1))));
        if budget >= MAX_FORWARDED_ASK_BUDGET {
            return MAX_FORWARDED_ASK_BUDGET;
        }
    }
    budget
}

/// What ONE forwarded ask actually established - the distinction this node had none of before
/// (dig-node#273).
///
/// # Why an empty `Vec` was not good enough
///
/// A timeout, an unreachable peer, a refusal and a genuine "I looked and found nobody" all used to
/// return `Vec::new()`, and that emptiness then reached `MissOutcome::NotFound` unchanged. Three of
/// those four establish NOTHING about whether the content exists; only the fourth does. Collapsing
/// them means one slow peer converts into an authoritative absence - a surface lying to the caller
/// about what this node knows, and a caller that believes a not-found stops looking.
///
/// So the emptiness of the record set and the PROVENNESS of the absence are two facts, and this type
/// keeps them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AskOutcome {
    /// The peer looked and reported these providers. **An empty vec here is a real answer** - that
    /// peer, and everyone it could reach, found nobody.
    Answered(Vec<ProviderRecord>),
    /// The peer answered, and said SO ITSELF that its own subtree did not finish looking
    /// (`result.absence_established == false`). The providers it did name are real candidates; the
    /// emptiness of the rest is not an absence.
    ///
    /// # This is the variant that makes the distinction CASCADE
    ///
    /// Without it a hop's honest "I could not tell" is read by its parent as a conclusive answer of
    /// nobody, and the parent reports a proven absence upward. An attacker two hops from a reader
    /// then manufactures a not-found by simply STALLING - no forgery, no path position, one held
    /// connection - because the honest intermediate between them correctly reports its uncertainty
    /// and nothing upstream reads it.
    AnsweredInconclusive(Vec<ProviderRecord>),
    /// The peer answered with a JSON-RPC error frame: it declined to look (its own hop cap, its own
    /// rate limit, recursion switched off there). Absence unproven.
    Refused,
    /// The budget was spent before an answer arrived. Absence unproven - and this is the case the
    /// arithmetic above exists to stop manufacturing.
    TimedOut,
    /// No connection, or the exchange failed mid-stream. Absence unproven.
    Unreachable,
}

impl AskOutcome {
    /// The providers this outcome named - none unless the peer actually answered.
    ///
    /// Test-only: production code matches on the variants, because the whole point of the type is
    /// that a caller cannot read the records without also seeing WHICH outcome produced them.
    #[cfg(test)]
    pub(crate) fn records(&self) -> &[ProviderRecord] {
        match self {
            Self::Answered(records) | Self::AnsweredInconclusive(records) => records,
            _ => &[],
        }
    }

    /// True when this outcome establishes that the content was genuinely not found by that peer.
    /// Every other variant means the peer did not look, or did not finish looking.
    #[cfg(test)]
    pub(crate) fn is_conclusive(&self) -> bool {
        matches!(self, Self::Answered(_))
    }

    /// The providers this outcome named, consumed - `Answered` and `AnsweredInconclusive` alike.
    ///
    /// Both carry real candidates: a hop that could not finish looking may still have found someone
    /// before it ran out, and discarding those would punish the honest report of uncertainty.
    pub(crate) fn into_records(self) -> Vec<ProviderRecord> {
        match self {
            Self::Answered(records) | Self::AnsweredInconclusive(records) => records,
            Self::Refused | Self::TimedOut | Self::Unreachable => Vec::new(),
        }
    }
}

/// Issue one `dig.getAvailability` to one connected peer and report the providers it named.
///
/// A seam, so the merge policy in [`crate::download::NodeContent::locate_holders`] is testable without
/// a network: the production implementation dials over dig-nat, and tests supply an asker that answers
/// from a fixture.
#[async_trait]
pub(crate) trait ForwardedAsk: Send + Sync {
    /// Ask `peer` (reachable at `addrs`) whether it - or anyone it knows - holds `content`, declaring
    /// `next_depth` as the hop budget already consumed and granting it `budget` of wall clock.
    ///
    /// Returns WHAT WAS ESTABLISHED, not merely what was found: an unreachable, silent or refusing
    /// peer is reported as such rather than as an answer of "nobody", because those are different
    /// facts and the caller has to be able to tell them apart (dig-node#273).
    ///
    /// `budget` is the time this ask may take IN TOTAL, already decremented by everything the chain
    /// above has spent. An implementation MUST NOT extend it.
    ///
    /// `ask_id` is the question's identity, and it is PASSED rather than minted because it must be
    /// echoed unchanged onto the wire: it is what lets the peer - and every hop beyond it - recognise
    /// a question that already reached them by another path (dig-node#273).
    async fn ask(
        &self,
        peer: &str,
        addrs: &[SocketAddr],
        content: &ContentId,
        next_depth: u64,
        budget: Duration,
        ask_id: AskId,
    ) -> AskOutcome;
}

/// The `dig.getAvailability` request body for `content` at hop budget `next_depth` — the SAME shape
/// any other caller sends, built from the same [`content_id_json`](crate::download::content_id_json)
/// item renderer the redirect uses, so the forwarded question is byte-identical to a direct one.
///
/// `ask_id` rides as hex under `params.ask_id`, the field
/// [`HopBudget::from_params`](crate::download::HopBudget::from_params) reads at the far end. A peer on
/// an older build ignores it and mints its own, which is the pre-dedup behaviour and never worse.
pub(crate) fn forwarded_request(
    content: &ContentId,
    next_depth: u64,
    budget: Duration,
    ask_id: AskId,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "dig.getAvailability",
        "params": {
            "items": [crate::download::content_id_json(content)],
            "redirect_depth": next_depth,
            "budget_ms": u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
            // The identity, hex-encoded, echoed exactly as received. THIS is what makes the seen-set
            // a dedup rather than a random-key generator: with the field absent, every hop's ingress
            // mints a fresh id, every claim succeeds, and a diamond in the graph re-walks itself.
            "ask_id": hex::encode(ask_id),
        },
    })
}

/// Await one peer exchange under `budget` and classify what it ESTABLISHED.
///
/// Split out of the dial so the classification is reachable without a network. `NatForwardedAsk::ask`
/// delegates its whole tail to this, so there is no second copy of the mapping and no way to bypass it
/// at the call site — which matters, because a timeout read as an empty answer is exactly the defect
/// dig-node#273 fixes and it lived in this function.
pub(crate) async fn awaited_outcome<F>(
    content: &ContentId,
    peer: &str,
    budget: Duration,
    exchange: F,
) -> AskOutcome
where
    F: std::future::Future<Output = Option<Value>>,
{
    match tokio::time::timeout(budget, exchange).await {
        Ok(Some(response)) => parse_forwarded_answer(content, &response),
        // Reached, but the exchange failed: a dial refused, a stream that would not open, a frame
        // that would not read. Nothing was established about the content.
        Ok(None) => {
            tracing::debug!(peer = %peer, "forwarded ask: unreachable");
            AskOutcome::Unreachable
        }
        // The budget ran out. Reported as ITSELF rather than as an empty answer, because this is
        // precisely the case that used to become an authoritative absence (dig-node#273).
        Err(_) => {
            tracing::debug!(peer = %peer, ?budget, "forwarded ask: timed out");
            AskOutcome::TimedOut
        }
    }
}

/// Read a `dig.getAvailability` response as an [`AskOutcome`].
///
/// A JSON-RPC **error frame** - what a peer at its hop cap, over its rate limit, or with recursion
/// switched off returns - is a [`Refused`](AskOutcome::Refused), never an answer of "nobody". A
/// `result` frame is an [`Answered`](AskOutcome::Answered) even when the provider list is empty,
/// because there the peer genuinely did look - UNLESS the peer itself said otherwise, in which case
/// it is an [`AnsweredInconclusive`](AskOutcome::AnsweredInconclusive). That last case is what makes
/// a downstream hop's uncertainty TRAVEL: see [`answered_conclusively`].
///
/// A frame that is neither is a peer that did not answer the question it was asked, which establishes
/// nothing: [`Unreachable`](AskOutcome::Unreachable). Reading it as an empty answer would hand any
/// peer a one-field way to manufacture an authoritative absence.
pub(crate) fn parse_forwarded_answer(content: &ContentId, response: &Value) -> AskOutcome {
    if response.get("error").is_some() {
        return AskOutcome::Refused;
    }
    if response.get("result").is_none() {
        return AskOutcome::Unreachable;
    }
    let records = parse_forwarded_providers(content, response);
    if answered_conclusively(response) {
        AskOutcome::Answered(records)
    } else {
        AskOutcome::AnsweredInconclusive(records)
    }
}

/// Whether the peer's own answer claims its subtree finished looking.
///
/// Reads `result.items[*].absence_established`, the field this node emits on the same verb. **Any
/// item saying `false` makes the whole answer inconclusive**, and an absent field reads as `true`.
///
/// The absent case is deliberately tolerant: a peer on a build predating the field cannot say
/// anything about its own certainty, and reading its silence as uncertainty would make every miss on
/// a mixed network inconclusive - the opposite lie, arriving by default rather than by attack.
///
/// A hop can of course LIE here, like anything else it tells us (NC-12) - but the value can only ever
/// WEAKEN the claim this node goes on to make, never strengthen it. Claiming `false` costs the liar a
/// retry it could have caused anyway by staying silent; claiming `true` is exactly the pre-existing
/// behaviour. There is no direction in which lying about this field buys reach.
fn answered_conclusively(response: &Value) -> bool {
    response
        .get("result")
        .and_then(|r| r.get("items"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .all(|item| {
            item.get("absence_established")
                .and_then(Value::as_bool)
                .unwrap_or(true)
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
        budget: Duration,
        ask_id: AskId,
    ) -> AskOutcome {
        let Some(peer_id) = PeerId::from_hex(peer) else {
            return AskOutcome::Unreachable;
        };
        if addrs.is_empty() {
            return AskOutcome::Unreachable;
        }
        // The full candidate list, not one collapsed address: `with_addrs` sorts it IPv6-first (§5.2)
        // and the fallback ladder needs every family to try.
        let target = dig_nat::PeerTarget::with_addrs(peer_id, addrs.to_vec(), &self.network_id);
        // The DIAL gets the leaf timeout even when the whole ask gets more: a peer we cannot reach is
        // unreachable now, and spending a 65s recursive budget on one unanswered handshake would let a
        // single black-holed address consume the entire question's time.
        let config =
            crate::net::full_nat_config(FORWARDED_ASK_LEAF_TIMEOUT.min(budget), self.stun_server);
        let request = forwarded_request(content, next_depth, budget, ask_id);

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

        awaited_outcome(content, peer, budget, exchange).await
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
        let request = forwarded_request(&content(), 3, Duration::from_millis(12_500));

        assert_eq!(request["method"], "dig.getAvailability");
        assert_eq!(request["params"]["redirect_depth"], json!(3));
        assert_eq!(
            request["params"]["budget_ms"],
            json!(12_500),
            "the TIME budget rides its own field, because it is monotone DECREASING while \
             redirect_depth is monotone increasing - one integer cannot honestly carry both, and \
             overloading it would let a hop grant itself hops by claiming time"
        );
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

    /// **Proves:** a JSON-RPC error frame - what a peer at the hop cap or over its rate limit returns
    /// - is a REFUSAL, and a refusal is not an answer of "nobody".
    ///
    /// **This test replaces `an_error_frame_yields_nobody`, which pinned the opposite** (dig-node#273).
    /// That test asserted a real property of the old code and was the reason the collapse survived: it
    /// made "an error frame means nobody holds it" look like the intended contract. It is intended
    /// that it changed.
    ///
    /// **Catches:** any implementation that keeps reading an error frame as an empty answer - which is
    /// a one-field censorship primitive, since a peer that simply refuses every ask suppresses every
    /// holder downstream of it AND makes the requestor confident about it.
    #[test]
    fn an_error_frame_is_a_refusal_and_not_an_answer_of_nobody() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32003, "message": "miss lookup rate limit exceeded" },
        });

        let outcome = parse_forwarded_answer(&content(), &response);

        assert!(
            outcome.records().is_empty(),
            "a refusal still names no candidates"
        );
        assert!(
            !outcome.is_conclusive(),
            "a refusal establishes NOTHING about whether the content exists - reading it as \
             'nobody holds it' is a censorship primitive costing one field"
        );
        assert_eq!(outcome, AskOutcome::Refused);
    }

    /// **Proves:** a `result` frame naming no providers IS an answer - the one case of the four that
    /// genuinely establishes an absence.
    ///
    /// **Fixture design:** this is the truthful control for the three unproven cases. Without it the
    /// suite could not distinguish "everything is inconclusive now" from "the right things are", and
    /// an implementation that marked every ask unproven would pass every other test here while making
    /// every miss on the network report as inconclusive.
    #[test]
    fn a_result_frame_naming_nobody_is_a_conclusive_answer() {
        let outcome = parse_forwarded_answer(&content(), &answer_with(json!([])));

        assert_eq!(outcome, AskOutcome::Answered(Vec::new()));
        assert!(
            outcome.is_conclusive(),
            "the peer looked, and reported that it found nobody"
        );
    }

    /// **Proves:** a frame that is neither a result nor an error - a peer answering something else
    /// entirely - establishes nothing.
    ///
    /// **Catches:** a parser that falls through to `Answered(vec![])`, which would let a peer
    /// manufacture an authoritative absence by replying with any well-formed JSON object at all.
    #[test]
    fn a_frame_that_is_neither_result_nor_error_establishes_nothing() {
        let outcome = parse_forwarded_answer(&content(), &json!({"jsonrpc": "2.0", "id": 1}));

        assert_eq!(outcome, AskOutcome::Unreachable);
        assert!(!outcome.is_conclusive());
    }

    /// **Proves:** an exchange that does not finish inside its budget is a TIMEOUT, in the
    /// production classifier rather than in a double.
    ///
    /// **Fixture design - a real future against a real (paused) clock.** The earlier version of this
    /// proof used a `ForwardedAsk` double that RETURNED `TimedOut` itself, which meant reverting the
    /// production mapping to `Answered(vec![])` broke nothing: the double asserted the verdict the
    /// code was supposed to reach. Measured, that revert came back green. Driving
    /// [`awaited_outcome`] with a future that outlives its budget is what makes the mapping
    /// load-bearing. `start_paused` keeps it instantaneous.
    ///
    /// **Catches:** the shipped behaviour, in which a timeout became an empty provider list and then
    /// an authoritative not-found.
    #[tokio::test(start_paused = true)]
    async fn an_exchange_that_outlives_its_budget_is_a_timeout_and_not_an_answer() {
        let slow = async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Some(answer_with(json!([])))
        };

        let outcome = awaited_outcome(&content(), "peer", Duration::from_secs(1), slow).await;

        assert!(
            !outcome.is_conclusive(),
            "a peer that never answered establishes nothing, so this must not become a not-found"
        );
        assert_eq!(outcome, AskOutcome::TimedOut);
    }

    /// **Proves:** an exchange that DOES finish inside its budget is classified on its content.
    ///
    /// **Fixture design:** the truthful control for the test above. Without it, an implementation that
    /// reported `TimedOut` unconditionally would pass every timeout assertion here while never
    /// answering anything - and the same budget is used for both, so the only difference is whether
    /// the future finished.
    #[tokio::test(start_paused = true)]
    async fn an_exchange_that_finishes_inside_its_budget_is_answered_on_its_content() {
        let prompt = async { Some(answer_with(json!([]))) };

        let outcome = awaited_outcome(&content(), "peer", Duration::from_secs(1), prompt).await;

        assert!(
            outcome.is_conclusive(),
            "the peer answered inside its budget, so its answer stands"
        );
        assert_eq!(outcome, AskOutcome::Answered(Vec::new()));
    }

    /// **Proves:** a failed exchange inside the budget is UNREACHABLE, not an answer of nobody.
    #[tokio::test(start_paused = true)]
    async fn a_failed_exchange_is_unreachable_and_not_an_answer() {
        let broken = async { None };

        let outcome = awaited_outcome(&content(), "peer", Duration::from_secs(1), broken).await;

        assert!(!outcome.is_conclusive());
        assert_eq!(outcome, AskOutcome::Unreachable);
    }

    /// **Proves the arithmetic that makes hop 2 reachable at all** (dig-node#273): a hop that will
    /// itself fan out is granted at least the work it is being asked to do.
    ///
    /// **Fixture design - the numbers come from the protocol, not from taste.** `fan_out` and
    /// `hop_cap` are read off `RecursionConfig::default()` rather than restated, so this moves with
    /// the canonical crate instead of pinning a private copy. The bound is checked from BOTH sides:
    /// a leaf gets exactly the leaf timeout (one over would be slack), and an intermediate hop gets
    /// at least `fan_out x` the budget of the hop below it (one under is the shipped defect).
    #[test]
    fn an_intermediate_hop_is_granted_at_least_the_work_it_must_do() {
        let config = dig_sex::discovery::RecursionConfig::default();
        let fan_out = config.fan_out;

        let leaf = ask_budget(0, fan_out);
        assert_eq!(
            leaf, FORWARDED_ASK_LEAF_TIMEOUT,
            "a hop with no hops left does exactly one ask"
        );

        let one_hop = ask_budget(1, fan_out);
        assert!(
            one_hop >= leaf * u32::from(fan_out),
            "a hop that must ask {fan_out} peers sequentially, each needing {leaf:?}, cannot be \
             given {one_hop:?} - this is the inequality whose violation made the recursion depth-1"
        );

        assert!(
            ask_budget(config.hop_cap, fan_out) >= one_hop * u32::from(fan_out),
            "and the same inequality holds at the originator, all the way up hop_cap"
        );
    }

    /// **Proves:** the budget is CLAMPED, so neither a large local config nor a hop naming an absurd
    /// budget on the wire can hold an inbound request open indefinitely.
    ///
    /// **Fixture design:** the input is chosen to be far past the ceiling rather than one step past
    /// it, because the failure being excluded is unbounded growth. The at-ceiling side is pinned by
    /// the default-config case above, which lands exactly on it.
    #[test]
    fn the_budget_is_clamped_however_deep_or_wide_the_configuration_claims_to_be() {
        assert_eq!(
            ask_budget(u8::MAX, u8::MAX),
            MAX_FORWARDED_ASK_BUDGET,
            "an untrusted or misconfigured breadth/depth cannot buy unbounded wall clock"
        );
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
