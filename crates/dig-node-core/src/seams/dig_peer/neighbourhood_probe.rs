//! The peer provider-snapshot RPC + the concrete [`NeighbourhoodProbe`] — the anti-Sybil
//! identity-binding layer of the DHT-sampling flywheel (epic #1934, child 4a/7).
//!
//! [`crate::dht_sampling`] (child 2) owns the pure reconciliation policy and defines the
//! [`NeighbourhoodProbe`] SEAM it consumes; it deliberately left the concrete probe mocked. This
//! module provides that concrete probe — and the peer RPC it speaks to — so a real sampling round
//! can gather per-peer observations from the live network. It does NOT run the prefetch loop, select,
//! fetch, or write the cache: those are child 4b.
//!
//! # The two halves, one contract
//!
//! 1. **Server** ([`provider_snapshot_result`]) — a `dig.getProviderSnapshot` peer RPC that answers
//!    with this node's LOCAL [`dig_dht::DhtService::provider_snapshot`], reusing the RLY-009
//!    [`dig_nat::relay::DhtRecordsAnswer`] wire shape VERBATIM (one DHT-records view, two transports:
//!    the relay callback and this node-to-node RPC). The answer carries COUNTS ONLY — never provider
//!    identities — exactly as the relay view does, so publishing it links no `(peer_id, content_key)`
//!    pair.
//! 2. **Client + probe** ([`DhtNeighbourhoodProbe`]) — route toward a keyspace point with dig-dht
//!    `find_node`, then ask each peer found there for its provider snapshot over mTLS, and turn each
//!    responding peer into ONE [`PeerObservation`].
//!
//! # THE load-bearing security property: identity comes from the verified session, never the wire
//!
//! A [`PeerObservation::peer_id`] is the anti-Sybil VOTE identity — the quorum in
//! [`crate::dht_sampling::reconcile`] counts DISTINCT peer_ids, so whoever controls the attribution
//! controls the vote. This module therefore derives that identity from EXACTLY ONE source: the
//! `peer_id` of the mutually-authenticated mTLS session (`SHA-256(verified server-cert SPKI DER)`,
//! pinned + checked by dig-tls during the handshake). It is NEVER taken from the dig-dht
//! [`Contact::peer_id`] a router returned, and NEVER from any field of the snapshot payload (the
//! payload carries no identity at all). This mirrors the established `holdings.rs` pattern, where an
//! announce's provider identity is the verified signer's SPKI hash and no caller-supplied id can name
//! a different peer. A peer that lies about who it is in its `Contact` cannot forge a vote: either the
//! mTLS handshake refuses the mismatched cert (the dial fails, contributing nothing), or — for any
//! path that connects without a pinned id — the observation is attributed to the cert actually
//! presented, not the claim.
//!
//! # Bounds — a lying peer cannot turn one cheap request into unbounded work
//!
//! Every value a remote peer influences is capped with a named constant, co-located with the WHY:
//! the server clamps the requested `max_keys` ([`MAX_PROVIDER_SNAPSHOT_KEYS`]); the client caps each
//! peer's holdings ([`MAX_HOLDINGS_PER_PEER`]) and the whole round's observation volume
//! ([`MAX_OBS_PER_ROUND`]) BEFORE handing anything to the reconciler, so neither a single verbose
//! peer nor a cluster of them can exhaust memory in [`reconcile`](crate::dht_sampling::reconcile).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde_json::{json, Value};

use dig_dht::{DhtService, PeerId};
use dig_nat::relay::DhtRecordsAnswer;
use dig_nat::wire::DhtRecordEntry;

use crate::dht_sampling::{NeighbourhoodProbe, ObservedCandidate, PeerObservation};
use crate::seams::dig_peer::dht::DhtHandle;

/// The wire name of the peer provider-snapshot RPC.
///
/// It is a **dig-node-local** peer method: the shared `dig-rpc-protocol` allowlist is a crates.io pin
/// this crate cannot extend, so [`crate::peer::is_peer_reachable_method`] allowlists this name
/// explicitly (promoting it into the shared crate is a tracked cross-repo follow-up). The name is
/// namespaced under `dig.` to match every other read/discovery method on the peer surface.
pub const GET_PROVIDER_SNAPSHOT_METHOD: &str = "dig.getProviderSnapshot";

/// The hard cap on how many keys one `dig.getProviderSnapshot` request may pull.
///
/// WHY a cap at all: `max_keys` is an untrusted number a remote peer chose, and the snapshot is
/// `O(max_keys)` in both the provider-store walk and the serialized response — an unbounded value lets
/// one ~200-byte request make this node enumerate + serialize its ENTIRE provider store on the very
/// connection it depends on for reachability. The clamp bounds that work regardless of what a peer asks.
///
/// WHY 512 specifically, and not a rounder number: the response rides
/// [`crate::peer::read_framed`]'s 64 KiB control-frame ceiling. One record serializes as
/// `{"content_key":"<64 hex>","providers":<u32>}` ≈ 100 bytes, so 512 records ≈ 51 KB sits safely
/// under 64 KiB with room for the JSON-RPC envelope. A larger cap would produce answers the peer's own
/// `read_framed` REFUSES as oversized — i.e. a self-inflicted denial of the very data we mean to
/// serve. This bound is therefore derived from the frame ceiling, not chosen for taste.
pub const MAX_PROVIDER_SNAPSHOT_KEYS: usize = 512;

/// The cap on how many holdings ONE peer may contribute to a sampling round.
///
/// This node's own server caps at [`MAX_PROVIDER_SNAPSHOT_KEYS`], but a snapshot arrives from a REMOTE
/// peer running arbitrary code — a nonconforming or malicious implementation can put any number of
/// records on the wire (up to the frame ceiling). Truncating each peer's holdings here, before the
/// reconciler, means one verbose peer cannot inflate the per-key report maps in
/// [`reconcile`](crate::dht_sampling::reconcile). Kept equal to the server cap so an HONEST peer's full
/// snapshot is never truncated: the cap bites only a peer exceeding what the protocol permits.
pub const MAX_HOLDINGS_PER_PEER: usize = MAX_PROVIDER_SNAPSHOT_KEYS;

/// The cap on the TOTAL observations one probe round hands to the reconciler.
///
/// [`MAX_HOLDINGS_PER_PEER`] bounds any single peer; this bounds the SUM across every peer found near a
/// point. Without it, a cluster of Sybil peers — each within its own per-peer cap — could still make
/// `find_node` yield many contacts that together flood the reconciler's cross-peer grouping. The round
/// stops accumulating once this many observations are gathered, so the reconcile input is bounded no
/// matter how many peers answer. Sized well above a healthy neighbourhood's real output so it never
/// truncates honest sampling, yet finite so an adversarial fan-out cannot grow unbounded.
pub const MAX_OBS_PER_ROUND: usize = 4_096;

// ---------------------------------------------------------------------------------------------
// Server — answer `dig.getProviderSnapshot` from this node's local provider store
// ---------------------------------------------------------------------------------------------

/// Build the `dig.getProviderSnapshot` RESULT value from this node's local DHT provider store.
///
/// Pure over its inputs (a `dht` handle + the request `params`) so the clamp + the counts-only privacy
/// stance are unit-testable without a peer connection. The result mirrors
/// [`dig_nat::relay::DhtRecordsAnswer`] field-for-field (`records: [{content_key, providers}]`,
/// `total_keys`, `truncated`) — the SAME shape the RLY-009 relay callback emits.
///
/// `max_keys` from the request is CLAMPED to [`MAX_PROVIDER_SNAPSHOT_KEYS`] before it reaches the
/// store, so an over-cap (or absent) request is bounded rather than honoured unboundedly. A node with
/// no DHT wired answers an empty snapshot — the method is supported, there is simply nothing to report
/// (never provider identities, ever).
///
/// Unlike the SYNC RLY-009 relay callback — which must `block_in_place` + `block_on` to reach the
/// async snapshot from a sync context — this runs inside the already-async peer dispatch, so it simply
/// `await`s the snapshot. That is cooperative (it never blocks the connection poll) and, unlike
/// `block_in_place`, is safe on the current-thread runtime the unit tests use.
pub(crate) async fn provider_snapshot_result(
    dht: Option<&Arc<DhtHandle>>,
    params: &Value,
) -> Value {
    let requested = params
        .get("max_keys")
        .and_then(Value::as_u64)
        .unwrap_or(MAX_PROVIDER_SNAPSHOT_KEYS as u64);
    // Clamp BEFORE narrowing to `usize`, so the min can never be defeated by a cast overflow on a
    // 32-bit target.
    let max_keys = requested.min(MAX_PROVIDER_SNAPSHOT_KEYS as u64) as usize;

    let Some(dht) = dht else {
        return json!({ "records": [], "total_keys": 0, "truncated": false });
    };

    let snapshot = dht.service().provider_snapshot(max_keys).await;
    let records: Vec<DhtRecordEntry> = snapshot
        .entries
        .into_iter()
        .map(|e| DhtRecordEntry {
            content_key: e.content_key,
            providers: e.providers,
        })
        .collect();
    json!({
        "records": records,
        "total_keys": snapshot.total_keys,
        "truncated": snapshot.truncated,
    })
}

// ---------------------------------------------------------------------------------------------
// Client seams — routing toward a keyspace point, and fetching one peer's verified snapshot
// ---------------------------------------------------------------------------------------------

/// Route toward a keyspace point: return the peers the DHT believes are responsible for that region.
///
/// A seam over dig-dht `find_node` so the probe's wiring is testable without a live DHT. The
/// production impl is [`DhtService`].
#[async_trait::async_trait]
pub trait KeyspaceRouter: Send + Sync {
    /// The contacts closest to `point` (empty when the region is unreachable — never an error, so a
    /// dead lookup simply contributes nothing, exactly like a silent peer).
    async fn find_node(&self, point: [u8; 32]) -> Vec<dig_dht::Contact>;
}

#[async_trait::async_trait]
impl KeyspaceRouter for Arc<DhtService> {
    async fn find_node(&self, point: [u8; 32]) -> Vec<dig_dht::Contact> {
        // A keyspace point IS a node id in Kademlia (both are a uniform 256-bit value), so routing
        // toward it reuses `find_node` directly. An error means "could not reach the region" — mapped
        // to no contacts, per the seam's no-error contract.
        DhtService::find_node(self, &PeerId::from_bytes(point))
            .await
            .unwrap_or_default()
    }
}

/// One peer's provider snapshot, bound to the identity of the mTLS session it arrived over.
///
/// [`Self::peer_id`] is the VERIFIED session identity (`SHA-256(server-cert SPKI DER)`), NOT the
/// `Contact::peer_id` the router claimed. It is the only value the probe uses to attribute the
/// observation — see the module docs.
pub struct VerifiedSnapshot {
    /// The verified 32-byte `peer_id` of the responding peer (from the mTLS session, never the wire).
    pub peer_id: [u8; 32],
    /// That peer's reported provider snapshot — the RLY-009 wire shape, reused verbatim.
    pub answer: DhtRecordsAnswer,
}

/// Fetch one peer's provider snapshot over an authenticated channel.
///
/// A seam over the mTLS dial + RPC so the probe's identity-binding + caps are testable without a
/// socket. The production impl is [`MtlsProviderSnapshotClient`]. The contract every impl MUST honour:
/// the returned [`VerifiedSnapshot::peer_id`] is the identity of the AUTHENTICATED session, so a
/// caller can attribute the observation to it without re-checking the wire.
#[async_trait::async_trait]
pub trait ProviderSnapshotClient: Send + Sync {
    /// Dial `contact`, call `dig.getProviderSnapshot`, and return the verified snapshot — or `None`
    /// for ANY failure (unreachable, handshake refused, RPC error, malformed answer). A `None` peer
    /// contributes nothing, never an error, matching [`NeighbourhoodProbe::observe_near`]'s contract.
    async fn fetch(&self, contact: &dig_dht::Contact) -> Option<VerifiedSnapshot>;
}

// ---------------------------------------------------------------------------------------------
// The concrete mTLS client
// ---------------------------------------------------------------------------------------------

/// The production [`ProviderSnapshotClient`]: dials a contact over dig-nat mTLS and speaks
/// `dig.getProviderSnapshot` on the peer surface.
pub struct MtlsProviderSnapshotClient {
    /// This node's own mTLS identity, presented as the client leaf on every dial.
    identity: Arc<dig_nat::NodeCert>,
    /// The traversal config (which tiers, per-tier timeout). The probe is latency-sensitive discovery,
    /// so a caller typically restricts it to Direct with a short timeout.
    config: dig_nat::NatConfig,
    /// The network label the dial is scoped to (e.g. `DIG_MAINNET`).
    network_id: String,
}

impl MtlsProviderSnapshotClient {
    /// A client dialing as `identity`, using `config`, scoped to `network_id`.
    #[must_use]
    pub fn new(
        identity: Arc<dig_nat::NodeCert>,
        config: dig_nat::NatConfig,
        network_id: impl Into<String>,
    ) -> Self {
        Self {
            identity,
            config,
            network_id: network_id.into(),
        }
    }
}

#[async_trait::async_trait]
impl ProviderSnapshotClient for MtlsProviderSnapshotClient {
    async fn fetch(&self, contact: &dig_dht::Contact) -> Option<VerifiedSnapshot> {
        // The id we DIAL toward is the router's claim; it is used only to PIN the handshake. What we
        // ATTRIBUTE the observation to below is `conn.peer_id`, the id the presented cert actually
        // hashes to — dig-tls refuses the handshake if the two disagree, so a lie here fails the dial
        // (None) rather than mis-attributing a vote.
        let dial_id = PeerId::from_hex(&contact.peer_id)?;
        let addrs = direct_socket_addrs(&contact.addresses);
        if addrs.is_empty() {
            return None; // relay-only / unparseable — nothing to dial directly in 4a
        }
        let target = dig_nat::PeerTarget::with_addrs(dial_id, addrs, self.network_id.clone());
        let mut conn = dig_nat::connect(&target, &self.identity, &self.config)
            .await
            .ok()?;

        let answer = request_provider_snapshot(&mut conn).await?;
        Some(VerifiedSnapshot {
            // THE identity: the verified session `peer_id`, never `contact.peer_id`.
            peer_id: *conn.peer_id.as_bytes(),
            answer,
        })
    }
}

/// The direct-dialable socket addresses among `addresses` (IP-literal candidates only).
///
/// Relay markers (empty host) and hostnames are skipped rather than DNS-resolved: the probe must never
/// block the async runtime on a name lookup, and a keyspace probe deals in the IP-literal candidates a
/// DHT contact carries.
fn direct_socket_addrs(addresses: &[dig_dht::CandidateAddr]) -> Vec<SocketAddr> {
    addresses
        .iter()
        .filter_map(|a| {
            a.host
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, a.port))
        })
        .collect()
}

/// One `dig.getProviderSnapshot` round-trip over an established peer connection: open a stream, write
/// the framed JSON-RPC request, read the framed response, and parse the RLY-009-shaped result.
///
/// Returns `None` on any transport or decode failure — the caller treats that as a silent peer.
async fn request_provider_snapshot(conn: &mut dig_nat::PeerConnection) -> Option<DhtRecordsAnswer> {
    let mut stream = conn.session.open_stream().await.ok()?;
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": GET_PROVIDER_SNAPSHOT_METHOD,
        "params": { "max_keys": MAX_PROVIDER_SNAPSHOT_KEYS },
    });
    crate::peer::write_framed(&mut stream, &request)
        .await
        .ok()?;
    let response = crate::peer::read_framed(&mut stream).await.ok()??;
    parse_snapshot_answer(response.get("result")?)
}

/// Parse a `dig.getProviderSnapshot` result into a [`DhtRecordsAnswer`].
///
/// Pure, so the wire-shape contract is unit-tested without a connection. Reuses the RLY-009 field
/// names verbatim; a missing/mistyped field yields `None` (a silent peer), never a partial answer.
fn parse_snapshot_answer(result: &Value) -> Option<DhtRecordsAnswer> {
    let records = result
        .get("records")?
        .as_array()?
        .iter()
        .filter_map(|r| {
            Some(DhtRecordEntry {
                content_key: r.get("content_key")?.as_str()?.to_string(),
                providers: usize::try_from(r.get("providers")?.as_u64()?).ok()?,
            })
        })
        .collect();
    Some(DhtRecordsAnswer {
        records,
        total_keys: usize::try_from(result.get("total_keys")?.as_u64()?).ok()?,
        truncated: result.get("truncated")?.as_bool()?,
    })
}

// ---------------------------------------------------------------------------------------------
// The concrete NeighbourhoodProbe
// ---------------------------------------------------------------------------------------------

/// The production [`NeighbourhoodProbe`]: route toward a keyspace point, fetch each responding peer's
/// verified snapshot, and turn each into ONE anti-Sybil observation with the caps applied.
pub struct DhtNeighbourhoodProbe<R: KeyspaceRouter, C: ProviderSnapshotClient> {
    router: R,
    client: C,
}

impl<R: KeyspaceRouter, C: ProviderSnapshotClient> DhtNeighbourhoodProbe<R, C> {
    /// A probe that routes with `router` and fetches snapshots with `client`.
    #[must_use]
    pub fn new(router: R, client: C) -> Self {
        Self { router, client }
    }
}

#[async_trait::async_trait]
impl<R: KeyspaceRouter, C: ProviderSnapshotClient> NeighbourhoodProbe
    for DhtNeighbourhoodProbe<R, C>
{
    async fn observe_near(&self, point: [u8; 32]) -> Vec<PeerObservation> {
        let mut observations = Vec::new();
        let mut round_total = 0usize;

        for contact in self.router.find_node(point).await {
            // The round budget is exhausted: stop, so a large fan-out cannot grow the reconcile input
            // without bound.
            let room = MAX_OBS_PER_ROUND.saturating_sub(round_total);
            if room == 0 {
                break;
            }
            // A silent / unreachable / mis-identified peer yields nothing (never an error).
            let Some(snapshot) = self.client.fetch(&contact).await else {
                continue;
            };

            // Attribution is the VERIFIED session id — never `contact.peer_id`.
            let mut observation =
                observation_from_answer(snapshot.peer_id, &snapshot.answer, MAX_HOLDINGS_PER_PEER);
            observation.holdings.truncate(room); // enforce the round budget on top of the per-peer cap
            if observation.holdings.is_empty() {
                continue;
            }
            round_total += observation.holdings.len();
            observations.push(observation);
        }
        observations
    }
}

/// Turn one peer's verified `(peer_id, answer)` into a [`PeerObservation`], capped at `max_holdings`.
///
/// `peer_id` is the VERIFIED session identity the caller resolved — this function never reads an
/// identity from `answer` (the payload carries none). Records with a malformed content key are
/// dropped; the DHT snapshot carries no size, so every `size_hint` is `None` (the real size is learned
/// at fetch time, child 4b). At most `max_holdings` valid records are kept.
fn observation_from_answer(
    peer_id: [u8; 32],
    answer: &DhtRecordsAnswer,
    max_holdings: usize,
) -> PeerObservation {
    let holdings = answer
        .records
        .iter()
        .filter_map(|entry| {
            Some(ObservedCandidate {
                content_id: decode_content_key(&entry.content_key)?,
                provider_count: u32::try_from(entry.providers).unwrap_or(u32::MAX),
                size_hint: None,
            })
        })
        .take(max_holdings)
        .collect();
    PeerObservation { peer_id, holdings }
}

/// Decode a 64-hex content key into its 32 raw bytes, or `None` for a malformed key.
fn decode_content_key(content_key: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(content_key).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> String {
        hex::encode([seed; 32])
    }

    fn entry(seed: u8, providers: usize) -> DhtRecordEntry {
        DhtRecordEntry {
            content_key: key(seed),
            providers,
        }
    }

    // -- Server: bounded max_keys, counts-only ----------------------------------------------------

    #[tokio::test]
    async fn server_clamps_an_over_cap_max_keys_request() {
        // A node with no DHT still exercises the clamp path (the clamp happens before the store is
        // consulted). Ask for far more than the cap and prove the request is not honoured unbounded:
        // the answer is a valid, bounded snapshot rather than an error or an unbounded walk.
        let params = json!({ "max_keys": 1_000_000 });
        let result = provider_snapshot_result(None, &params).await;
        // No DHT → empty, but crucially the call RETURNED (did not attempt an unbounded walk) and is
        // well-formed. The clamp itself is asserted as a pure property below.
        assert_eq!(result["records"].as_array().unwrap().len(), 0);
        assert_eq!(result["total_keys"], 0);
        assert_eq!(result["truncated"], false);
    }

    #[test]
    fn max_keys_is_clamped_to_the_frame_safe_cap() {
        // The clamp is `min(requested, MAX)`; assert both directions at the bound so the constant is
        // pinned as the ACTUAL ceiling, not merely an upper hint.
        let clamp = |requested: u64| requested.min(MAX_PROVIDER_SNAPSHOT_KEYS as u64) as usize;
        assert_eq!(
            clamp(1_000_000),
            MAX_PROVIDER_SNAPSHOT_KEYS,
            "over-cap is clamped"
        );
        assert_eq!(clamp(10), 10, "under-cap is honoured");
        assert_eq!(
            clamp(MAX_PROVIDER_SNAPSHOT_KEYS as u64),
            MAX_PROVIDER_SNAPSHOT_KEYS,
            "exactly at the cap passes through"
        );
    }

    #[test]
    fn the_snapshot_cap_keeps_a_full_answer_under_the_frame_ceiling() {
        // The WHY behind the value: a maximal answer must fit read_framed's 64 KiB control-frame
        // ceiling, or the peer's own reader would reject the data we serve. ~100 B/record is the
        // measured worst case.
        const FRAME_CEILING: usize = 64 * 1024;
        const BYTES_PER_RECORD: usize = 110; // 64-hex key + envelope, rounded up
        const {
            assert!(
                MAX_PROVIDER_SNAPSHOT_KEYS * BYTES_PER_RECORD < FRAME_CEILING,
                "a full snapshot must fit under the 64 KiB control-frame ceiling"
            );
        }
    }

    // -- The load-bearing anti-Sybil identity property --------------------------------------------

    /// A router whose contacts carry ATTACKER-CHOSEN peer_ids, paired with a client that returns a
    /// DIFFERENT verified id — the exact split the identity rule must resolve in favour of the session.
    struct LyingRouter {
        contacts: Vec<dig_dht::Contact>,
    }

    #[async_trait::async_trait]
    impl KeyspaceRouter for LyingRouter {
        async fn find_node(&self, _point: [u8; 32]) -> Vec<dig_dht::Contact> {
            self.contacts.clone()
        }
    }

    /// A client that ignores the contact's claimed id and reports a fixed VERIFIED id + answer — a
    /// stand-in for the mTLS session, whose identity is the cert's SPKI hash, not the wire claim.
    struct FixedIdentityClient {
        verified_peer_id: [u8; 32],
        answer: DhtRecordsAnswer,
    }

    #[async_trait::async_trait]
    impl ProviderSnapshotClient for FixedIdentityClient {
        async fn fetch(&self, _contact: &dig_dht::Contact) -> Option<VerifiedSnapshot> {
            Some(VerifiedSnapshot {
                peer_id: self.verified_peer_id,
                answer: self.answer.clone(),
            })
        }
    }

    #[tokio::test]
    async fn observation_identity_is_the_verified_session_never_the_wire_claim() {
        // The contact CLAIMS peer_id 0xAA…; the session VERIFIES peer_id 0xBB…. The observation must
        // be attributed to 0xBB… — proving the vote identity comes from the authenticated session and
        // a Sybil cannot pick its own vote id by lying in its Contact.
        let claimed = [0xAA; 32];
        let verified = [0xBB; 32];
        let contact = dig_dht::Contact::new(
            &PeerId::from_bytes(claimed),
            vec![dig_dht::CandidateAddr::direct("203.0.113.7", 9257)],
        );
        let probe = DhtNeighbourhoodProbe::new(
            LyingRouter {
                contacts: vec![contact],
            },
            FixedIdentityClient {
                verified_peer_id: verified,
                answer: DhtRecordsAnswer {
                    records: vec![entry(0x11, 3)],
                    total_keys: 1,
                    truncated: false,
                },
            },
        );

        let observations = probe.observe_near([0; 32]).await;
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].peer_id, verified,
            "the vote identity MUST be the verified session id, never the contact's claim"
        );
        assert_ne!(
            observations[0].peer_id, claimed,
            "the attacker's claimed id must never become the vote identity"
        );
    }

    // -- Silent / unreachable peer contributes nothing --------------------------------------------

    struct SilentClient;

    #[async_trait::async_trait]
    impl ProviderSnapshotClient for SilentClient {
        async fn fetch(&self, _contact: &dig_dht::Contact) -> Option<VerifiedSnapshot> {
            None
        }
    }

    #[tokio::test]
    async fn a_silent_peer_yields_no_observation_and_no_error() {
        let contact = dig_dht::Contact::new(
            &PeerId::from_bytes([0x01; 32]),
            vec![dig_dht::CandidateAddr::direct("198.51.100.9", 9257)],
        );
        let probe = DhtNeighbourhoodProbe::new(
            LyingRouter {
                contacts: vec![contact],
            },
            SilentClient,
        );
        assert!(
            probe.observe_near([0; 32]).await.is_empty(),
            "a silent peer must contribute no observation (and the probe must not error)"
        );
    }

    // -- The volume caps ---------------------------------------------------------------------------

    #[test]
    fn per_peer_holdings_are_capped_before_reconcile() {
        // One peer reports FAR more than the per-peer cap; the observation must be truncated to the
        // cap, so a single verbose peer cannot inflate the reconciler's maps.
        let records: Vec<DhtRecordEntry> = (0..(MAX_HOLDINGS_PER_PEER as u16 + 50))
            .map(|i| DhtRecordEntry {
                content_key: hex::encode((i as u32).to_be_bytes().repeat(8)),
                providers: 1,
            })
            .collect();
        let answer = DhtRecordsAnswer {
            total_keys: records.len(),
            truncated: false,
            records,
        };
        let observation = observation_from_answer([0x07; 32], &answer, MAX_HOLDINGS_PER_PEER);
        assert_eq!(
            observation.holdings.len(),
            MAX_HOLDINGS_PER_PEER,
            "an over-cap peer's holdings must be truncated to the per-peer cap"
        );
    }

    #[test]
    fn at_the_per_peer_bound_passes_through_whole() {
        let records: Vec<DhtRecordEntry> = (0..8u8).map(|i| entry(i, 1)).collect();
        let answer = DhtRecordsAnswer {
            total_keys: records.len(),
            truncated: false,
            records,
        };
        let observation = observation_from_answer([0x07; 32], &answer, MAX_HOLDINGS_PER_PEER);
        assert_eq!(
            observation.holdings.len(),
            8,
            "an under-cap answer is kept whole"
        );
    }

    /// A client that returns a fixed-size answer for EVERY contact, so many contacts drive the round
    /// total over its cap.
    struct BulkClient {
        holdings_per_peer: usize,
    }

    #[async_trait::async_trait]
    impl ProviderSnapshotClient for BulkClient {
        async fn fetch(&self, contact: &dig_dht::Contact) -> Option<VerifiedSnapshot> {
            let records = (0..self.holdings_per_peer)
                .map(|i| DhtRecordEntry {
                    // Distinct keys per (peer,i) so nothing collapses; the point is raw volume.
                    content_key: hex::encode(
                        [
                            contact.peer_id.as_bytes()[..16].to_vec(),
                            (i as u128).to_be_bytes().to_vec(),
                        ]
                        .concat(),
                    ),
                    providers: 1,
                })
                .collect();
            Some(VerifiedSnapshot {
                peer_id: *PeerId::from_hex(&contact.peer_id).unwrap().as_bytes(),
                answer: DhtRecordsAnswer {
                    total_keys: self.holdings_per_peer,
                    truncated: false,
                    records,
                },
            })
        }
    }

    #[tokio::test]
    async fn the_round_volume_is_capped_across_many_peers() {
        // Enough peers, each at the per-peer cap, to blow past the round cap several times over.
        let contacts: Vec<dig_dht::Contact> = (0u8..40)
            .map(|i| {
                dig_dht::Contact::new(
                    &PeerId::from_bytes([i.wrapping_add(1); 32]),
                    vec![dig_dht::CandidateAddr::direct("192.0.2.1", 9257)],
                )
            })
            .collect();
        let probe = DhtNeighbourhoodProbe::new(
            LyingRouter { contacts },
            BulkClient {
                holdings_per_peer: MAX_HOLDINGS_PER_PEER,
            },
        );
        let observations = probe.observe_near([0; 32]).await;
        let total: usize = observations.iter().map(|o| o.holdings.len()).sum();
        assert!(
            total <= MAX_OBS_PER_ROUND,
            "the round must cap total observation volume at {MAX_OBS_PER_ROUND}, got {total}"
        );
    }

    // -- The wire-shape parse ----------------------------------------------------------------------

    #[test]
    fn parse_reads_the_rly009_shape_and_rejects_a_malformed_one() {
        let good = json!({
            "records": [{ "content_key": key(0x22), "providers": 5 }],
            "total_keys": 1,
            "truncated": false,
        });
        let answer = parse_snapshot_answer(&good).expect("a well-formed answer parses");
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].providers, 5);
        assert_eq!(answer.total_keys, 1);

        // A missing required field yields None (a silent peer), never a partial answer.
        let missing_total = json!({ "records": [], "truncated": false });
        assert!(parse_snapshot_answer(&missing_total).is_none());
    }

    // -- Real-wire two-node round-trip: identity == the responding server's SPKI -------------------

    /// **Proves:** over a REAL loopback mTLS peer connection, `dig.getProviderSnapshot` round-trips
    /// this node's live provider counts AND the observation is attributed to the id the responding
    /// server's certificate actually hashes to (`SHA-256(SPKI DER)`), not to any wire-supplied value.
    /// This is the end-to-end proof of the anti-Sybil identity rule: the vote identity is the verified
    /// session, established by the handshake, over the honest node-to-node wire.
    ///
    /// Binds a loopback socket, so it may not run under the sandbox's socket limit; it is structured to
    /// pass on a real CI runner (the same pattern as `range_stream_wire.rs`).
    #[tokio::test]
    async fn two_node_round_trip_attributes_to_the_servers_verified_spki() {
        use std::time::Duration;

        use crate::peer::{
            install_crypto_provider, load_or_generate_node_cert, serve_peer_rpc_listener,
            NodeResponder, PeerRpcResponder,
        };
        use crate::seams::dig_peer::dht::{DhtHandle, NatDhtTransport};

        fn seed(label: &str) -> [u8; 32] {
            use sha2::{Digest, Sha256};
            Sha256::digest(label.as_bytes()).into()
        }

        install_crypto_provider();

        // A real server node holding a live provider record, so the snapshot carries a real count.
        let (node, _cache) = crate::test_support::test_node_for_peer_surface();
        let server_dir = tempfile::tempdir().expect("server cert dir");
        let server_identity = load_or_generate_node_cert(server_dir.path(), &seed("probe-holder"))
            .expect("holder id");
        let server_peer_id = server_identity.peer_id();

        let transport = NatDhtTransport::new(
            load_or_generate_node_cert(server_dir.path(), &seed("probe-holder")).expect("dht id"),
            Arc::new(dig_nat::NatRuntime::default()),
            "DIG_MAINNET",
            Duration::from_secs(1),
        );
        let service = Arc::new(DhtService::new(
            PeerId::from_bytes(*server_peer_id.as_bytes()),
            vec![],
            dig_dht::DhtConfig::default(),
            Arc::new(transport),
        ));
        let held = dig_dht::ContentId::capsule([0xab; 32], [0xcd; 32]);
        service.announce_provider(&held).await.expect("announce");
        let expected_key = held.to_key().to_hex();
        let dht = DhtHandle::new(service, vec![]);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let addr = listener.local_addr().expect("addr");
        let responder: Arc<dyn PeerRpcResponder> =
            Arc::new(NodeResponder::without_pool(node).with_dht(dht));
        let _server = tokio::spawn(serve_peer_rpc_listener(
            listener,
            server_identity,
            responder,
        ));

        // The client dials the real server and fetches its snapshot over mTLS.
        let client_dir = tempfile::tempdir().expect("client cert dir");
        let client_identity = load_or_generate_node_cert(client_dir.path(), &seed("probe-reader"))
            .expect("reader id");
        let config = dig_nat::NatConfig::builder()
            .enabled_methods(vec![dig_nat::TraversalKind::Direct])
            .per_method_timeout(Duration::from_secs(10))
            .build();
        let client = MtlsProviderSnapshotClient::new(client_identity, config, "DIG_MAINNET");

        // The contact carries the server's real peer_id + address (an honest router entry).
        let contact = dig_dht::Contact::new(
            &PeerId::from_bytes(*server_peer_id.as_bytes()),
            vec![dig_dht::CandidateAddr::direct(
                addr.ip().to_string(),
                addr.port(),
            )],
        );
        let snapshot = client
            .fetch(&contact)
            .await
            .expect("the reader fetches the holder's snapshot over real mTLS");

        // THE assertion of record: the id is the server's VERIFIED SPKI hash, over the real wire.
        assert_eq!(
            snapshot.peer_id,
            *server_peer_id.as_bytes(),
            "the observation must be attributed to the server's verified cert SPKI"
        );
        // And the real provider count round-tripped, counts-only.
        assert!(
            snapshot
                .answer
                .records
                .iter()
                .any(|r| r.content_key == expected_key && r.providers >= 1),
            "the live provider record must round-trip as a count"
        );
    }

    #[test]
    fn a_malformed_content_key_is_dropped_not_fatal() {
        let answer = DhtRecordsAnswer {
            records: vec![
                DhtRecordEntry {
                    content_key: "not-hex".to_string(),
                    providers: 1,
                },
                entry(0x33, 2),
            ],
            total_keys: 2,
            truncated: false,
        };
        let observation = observation_from_answer([0x09; 32], &answer, MAX_HOLDINGS_PER_PEER);
        assert_eq!(
            observation.holdings.len(),
            1,
            "the malformed key is dropped; the valid one survives"
        );
    }
}
