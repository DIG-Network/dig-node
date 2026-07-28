//! Adversarial tests for the opcode-222 holdings ingress (#1429) — the authenticated path into the
//! local dig-dht provider set.
//!
//! Each test names the property it pins and is built against the NEAREST WRONG implementation, not
//! merely against the correct one. Two fixture disciplines are held throughout:
//!
//! - **A truthful control actor is always present.** Every censorship/flood test keeps an honest
//!   holder in the sink whose record must SURVIVE, because a test where every record is expendable
//!   cannot tell "removed only the liar's record" from "removed every record for that key".
//! - **Time is pinned.** `NOW` is an explicit fixture constant threaded through every call, so no
//!   assertion accidentally depends on wall-clock (an expiry passed as `100` through a wall-clock API
//!   is already expired by ~1.8 billion seconds and silently exercises only the expired path).
//!
//! Numeric bounds are pinned from BOTH sides: at-bound must pass, one-over must fail.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use dig_dht::{ContentId, ProviderRecord};
use dig_gossip::{
    frame_holdings_announce, CandidateAddr as GossipAddr, EcdsaHoldingsSigner, HoldingsAnnounce,
    HoldingsDelta, HoldingsError, HOLDINGS_MAX_CHANGES,
};
use dig_node_core::seams::dig_peer::holdings::{
    announcement_for, deltas_for, run_holdings_ingest, split_batches, AnnounceTransport, Applied,
    HoldingsBroadcaster, HoldingsIngress, HoldingsSink, IngressLimits, Rejected,
    ADVERTISED_TTL_SECS, MAX_ANNOUNCES_PER_PROVIDER, MAX_ANNOUNCE_AGE_SECS, MAX_DELTAS_PER_SENDER,
    RATE_WINDOW_SECS,
};

/// The pinned fixture clock (Unix seconds, 2026-07-01T00:00:00Z). Never `SystemTime::now()`.
const NOW: u64 = 1_782_000_000;

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// A real §5.2 peer identity: a P-256 leaf whose SPKI DER hashes to its `peer_id`.
struct TestPeer {
    signer: EcdsaHoldingsSigner,
    peer_id_hex: String,
}

impl TestPeer {
    fn new() -> Self {
        let kp = rcgen::KeyPair::generate().expect("generate P-256 leaf key pair");
        let spki = kp.public_key_der();
        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &kp.serialize_der(),
            &rng,
        )
        .expect("the generated key pair is a valid P-256 PKCS#8");
        let peer_id_hex = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&spki));
        Self {
            signer: EcdsaHoldingsSigner::new(key_pair, spki),
            peer_id_hex,
        }
    }

    /// Sign `changes` as this peer at `seq`, dated at the fixture clock.
    fn announce(&self, seq: u64, changes: Vec<HoldingsDelta>) -> HoldingsAnnounce {
        self.announce_at(seq, NOW, changes)
    }

    /// [`Self::announce`] with an explicit signed `announced_at`, for the freshness bound.
    fn announce_at(
        &self,
        seq: u64,
        announced_at: u64,
        changes: Vec<HoldingsDelta>,
    ) -> HoldingsAnnounce {
        HoldingsAnnounce::new_signed(&self.signer, seq, announced_at, changes)
            .expect("the fixture batch is within HOLDINGS_MAX_CHANGES")
    }
}

/// A deterministic content id from a single seed byte.
fn content(seed: u8) -> ContentId {
    ContentId::capsule([seed; 32], [seed ^ 0xff; 32])
}

/// The 64-hex dig-dht provider-store key for a content id.
fn key_hex(id: &ContentId) -> String {
    id.to_key().to_hex()
}

fn add_delta(id: &ContentId) -> HoldingsDelta {
    HoldingsDelta::Add {
        content_key: *id.to_key().as_bytes(),
        addresses: vec![GossipAddr {
            host: "::1".to_string(),
            port: 9_257,
        }],
        expires_at: NOW + ADVERTISED_TTL_SECS,
    }
}

fn remove_delta(id: &ContentId) -> HoldingsDelta {
    HoldingsDelta::Remove {
        content_key: *id.to_key().as_bytes(),
    }
}

/// An observable stand-in for the dig-dht provider store: a set of `(content_key, provider)` pairs.
///
/// It models the ONE property the ingress must not violate — that a record is owned by a specific
/// provider — so a "remove every provider of this key" implementation is observably different from a
/// correct one. The live `DhtService` is exercised by the real-wire test instead.
#[derive(Default)]
struct RecordingSink {
    records: Mutex<BTreeSet<(String, String)>>,
}

impl RecordingSink {
    /// Pre-seed a record so a later retract has a real victim to spare or destroy.
    fn seed(&self, id: &ContentId, provider: &str) {
        self.records
            .lock()
            .expect("sink mutex")
            .insert((key_hex(id), provider.to_string()));
    }

    fn holds(&self, id: &ContentId, provider: &str) -> bool {
        self.records
            .lock()
            .expect("sink mutex")
            .contains(&(key_hex(id), provider.to_string()))
    }

    fn len(&self) -> usize {
        self.records.lock().expect("sink mutex").len()
    }
}

#[async_trait::async_trait]
impl HoldingsSink for RecordingSink {
    async fn ingest(&self, record: ProviderRecord) -> bool {
        self.records
            .lock()
            .expect("sink mutex")
            .insert((record.content_key, record.provider_peer_id));
        true
    }

    async fn remove(&self, content_key: &str, provider_peer_id: &str) -> bool {
        self.records
            .lock()
            .expect("sink mutex")
            .remove(&(content_key.to_string(), provider_peer_id.to_string()))
    }
}

/// A sink that keeps every ingested [`ProviderRecord`] intact.
///
/// [`RecordingSink`] projects each record to `(content_key, provider)`, which is the right narrowness
/// for the attribution tests but physically cannot express an address-count or expiry lie. Where the
/// property under test is about a field that projection discards, the double is WIDENED rather than the
/// assertion weakened.
#[derive(Default)]
struct RecordingRecords {
    records: Mutex<Vec<ProviderRecord>>,
}

#[async_trait::async_trait]
impl HoldingsSink for RecordingRecords {
    async fn ingest(&self, record: ProviderRecord) -> bool {
        self.records.lock().expect("sink mutex").push(record);
        true
    }

    async fn remove(&self, _content_key: &str, _provider_peer_id: &str) -> bool {
        false
    }
}

/// A local-only [`DhtService`]: its transport reaches nobody, so it serves purely as a real sink.
fn local_dht_service(port: u16) -> Arc<dig_dht::DhtService> {
    struct Unreachable;
    #[async_trait::async_trait]
    impl dig_dht::DhtTransport for Unreachable {
        async fn rpc(
            &self,
            _from: &dig_dht::Contact,
            _target: &dig_dht::Contact,
            _request: &dig_dht::DhtRequest,
        ) -> Result<dig_dht::DhtResponse, dig_dht::DhtError> {
            Err(dig_dht::DhtError::Transport("unreachable".to_string()))
        }
    }
    Arc::new(dig_dht::DhtService::new(
        dig_dht::PeerId::from_bytes([0x5du8; 32]),
        vec![dig_dht::CandidateAddr::direct("::1".to_string(), port)],
        dig_dht::DhtConfig::default(),
        Arc::new(Unreachable),
    ))
}

/// An ingress for a node whose own peer_id is `self_peer`, with the production limits.
fn ingress(self_peer: &str) -> HoldingsIngress {
    HoldingsIngress::new(self_peer.to_string())
}

// ---------------------------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------------------------

/// PROPERTY: an inventory delta becomes adds-then-removes over the DHT content KEYS (not the raw
/// content ids), with the advertised expiry anchored to the caller's clock.
///
/// Nearest wrong implementation: encoding `store_id`/`root` bytes directly instead of
/// `ContentId::to_key()`. The fixture uses ids whose key differs from every constituent byte array,
/// so the wrong encoding cannot coincide with the right one.
#[test]
fn deltas_encode_dht_content_keys_and_the_pinned_expiry() {
    let gained = [content(1), content(2)];
    let lost = [content(3)];
    let addrs = [GossipAddr {
        host: "::1".to_string(),
        port: 9_257,
    }];

    let deltas = deltas_for(NOW, &gained, &lost, &addrs);

    assert_eq!(deltas.len(), 3, "two adds then one remove");
    match &deltas[0] {
        HoldingsDelta::Add {
            content_key,
            addresses,
            expires_at,
        } => {
            assert_eq!(
                content_key,
                gained[0].to_key().as_bytes(),
                "the wire carries the DHT content KEY, not the store/root bytes"
            );
            assert_eq!(
                addresses, &addrs,
                "the announced addresses are signed as-is"
            );
            assert_eq!(
                *expires_at,
                NOW + ADVERTISED_TTL_SECS,
                "expiry is anchored to the caller's clock, not wall-clock"
            );
        }
        other => panic!("expected the first delta to be an Add, got {other:?}"),
    }
    assert_eq!(
        deltas[2],
        remove_delta(&lost[0]),
        "a lost id becomes a Remove for the same content key"
    );
}

/// PROPERTY: nothing to announce produces no announcement (so an idle node floods nothing).
#[test]
fn an_empty_inventory_delta_produces_no_announcement() {
    let peer = TestPeer::new();
    let none = announcement_for(&peer.signer, 1, NOW, &[], &[], &[])
        .expect("an empty batch is not an error");
    assert!(none.is_none(), "an idle node must not flood an empty frame");
}

/// PROPERTY: a batch larger than the protocol's own cap is REFUSED, never truncated — truncation
/// would silently drop a retract and leave the node advertising content it no longer serves.
///
/// The fixture size is taken from the protocol limit (`HOLDINGS_MAX_CHANGES + 1`), and the bound is
/// pinned from both sides: exactly at the cap must succeed.
#[test]
fn an_oversized_batch_is_refused_and_the_cap_itself_is_accepted() {
    let peer = TestPeer::new();
    let at_cap: Vec<_> = (0..HOLDINGS_MAX_CHANGES)
        .map(|i| add_delta(&content(u8::try_from(i % 251).unwrap_or(0))))
        .collect();
    assert!(
        HoldingsAnnounce::new_signed(&peer.signer, 1, NOW, at_cap.clone()).is_ok(),
        "a batch of exactly HOLDINGS_MAX_CHANGES must be accepted (at-bound passes)"
    );

    let mut one_over = at_cap;
    one_over.push(remove_delta(&content(200)));
    assert!(
        matches!(
            HoldingsAnnounce::new_signed(&peer.signer, 1, NOW, one_over),
            Err(HoldingsError::TooManyChanges { .. })
        ),
        "one delta over the cap must be refused, not truncated (one-over fails)"
    );
}

/// PROPERTY: splitting preserves EVERY delta and its order across batch boundaries.
///
/// Nearest wrong implementation: truncating to the first batch, which would silently drop retracts.
/// The fixture is `2 × HOLDINGS_MAX_CHANGES + 1` deltas — sized from the protocol limit so it
/// straddles two boundaries rather than one.
#[test]
fn splitting_preserves_every_delta_and_its_order() {
    let total = 2 * HOLDINGS_MAX_CHANGES + 1;
    let deltas: Vec<_> = (0..total)
        .map(|i| remove_delta(&content(u8::try_from(i % 251).unwrap_or(0))))
        .collect();

    let batches = split_batches(deltas.clone());

    assert_eq!(batches.len(), 3, "257 deltas straddle two batch boundaries");
    assert!(
        batches.iter().all(|b| b.len() <= HOLDINGS_MAX_CHANGES),
        "no batch may exceed the protocol cap"
    );
    let flattened: Vec<_> = batches.into_iter().flatten().collect();
    assert_eq!(
        flattened, deltas,
        "splitting must lose no delta and reorder none"
    );
    assert!(
        split_batches(Vec::new()).is_empty(),
        "nothing to say produces no batch"
    );
}

// ---------------------------------------------------------------------------------------------
// Ingress — authenticity + attribution
// ---------------------------------------------------------------------------------------------

/// PROPERTY: a verified add is attributed to the SIGNER, and to the signer alone.
///
/// Nearest wrong implementation: attributing the record to the transport sender. The fixture makes
/// sender and provider DIFFERENT peers (a relayed flood, the normal case), so the two cannot coincide.
#[tokio::test]
async fn a_verified_add_is_attributed_to_the_signer_not_the_relaying_sender() {
    let holder = TestPeer::new();
    let relayer = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(7);

    let applied = ingress(&us.peer_id_hex)
        .accept(
            &sink,
            &relayer.peer_id_hex,
            &holder.announce(1, vec![add_delta(&id)]),
            NOW,
        )
        .await
        .expect("a correctly signed announce relayed by a third peer is accepted");

    assert_eq!(
        applied,
        Applied {
            ingested: 1,
            removed: 0
        }
    );
    assert!(
        sink.holds(&id, &holder.peer_id_hex),
        "the record must name the SIGNER as the holder"
    );
    assert!(
        !sink.holds(&id, &relayer.peer_id_hex),
        "the relaying peer must never be recorded as a holder of content it only forwarded"
    );
}

/// PROPERTY (H2, the censorship gate): a retract can only ever remove the SIGNER's own record.
///
/// This is the test the whole attribution invariant rests on. The fixture keeps a truthful control
/// holder — `honest` also provides the same content key — so the assertion can distinguish
/// "removed only the liar's record" from "removed every record for that key". A single-holder
/// fixture would pass under both implementations and prove nothing.
#[tokio::test]
async fn a_retract_cannot_delist_another_peers_record() {
    let attacker = TestPeer::new();
    let honest = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(9);

    // Two holders of the SAME key: the honest control, and the attacker itself.
    sink.seed(&id, &honest.peer_id_hex);
    sink.seed(&id, &attacker.peer_id_hex);

    let applied = ingress(&us.peer_id_hex)
        .accept(
            &sink,
            &attacker.peer_id_hex,
            &attacker.announce(1, vec![remove_delta(&id)]),
            NOW,
        )
        .await
        .expect(
            "a validly signed retract is accepted — it just cannot reach another peer's record",
        );

    assert_eq!(
        applied,
        Applied {
            ingested: 0,
            removed: 1
        },
        "exactly one record — the attacker's own — is removed"
    );
    assert!(
        sink.holds(&id, &honest.peer_id_hex),
        "the honest holder's record MUST survive an attacker's retract for the same content key"
    );
    assert!(
        !sink.holds(&id, &attacker.peer_id_hex),
        "the signer's own record is the one that goes"
    );
}

/// PROPERTY: a forged signature is rejected fail-closed and mutates nothing.
///
/// Nearest wrong implementation: verifying but ingesting anyway (logging the error). The sink is
/// seeded with a control record so "nothing changed" is observable rather than trivially true.
#[tokio::test]
async fn a_forged_signature_is_rejected_and_mutates_nothing() {
    let holder = TestPeer::new();
    let honest = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(11);
    sink.seed(&id, &honest.peer_id_hex);

    // A validly-formed announce whose signature has one flipped bit — the cheapest possible forgery.
    let mut forged = holder.announce(1, vec![add_delta(&id), remove_delta(&id)]);
    let last = forged.signature.len() - 1;
    forged.signature[last] ^= 0x01;

    let rejected = ingress(&us.peer_id_hex)
        .accept(&sink, &holder.peer_id_hex, &forged, NOW)
        .await
        .expect_err("a forged signature must be rejected");

    assert_eq!(
        rejected,
        Rejected::Unverified(HoldingsError::InvalidSignature)
    );
    assert_eq!(sink.len(), 1, "no record was added or removed");
    assert!(sink.holds(&id, &honest.peer_id_hex));
}

/// PROPERTY: an announce whose carried `peer_id` does not hash from its carried SPKI is rejected —
/// the impersonation attempt, where an attacker names a victim as the provider.
#[tokio::test]
async fn an_announce_claiming_another_peers_id_is_rejected() {
    let attacker = TestPeer::new();
    let victim = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(13);

    // The attacker signs with its OWN key but claims to be the victim.
    let mut impersonating = attacker.announce(1, vec![add_delta(&id)]);
    impersonating.provider_peer_id = victim.peer_id_hex.clone();

    let rejected = ingress(&us.peer_id_hex)
        .accept(&sink, &attacker.peer_id_hex, &impersonating, NOW)
        .await
        .expect_err("a peer_id that does not hash from the carried SPKI must be rejected");

    assert_eq!(
        rejected,
        Rejected::Unverified(HoldingsError::PeerIdMismatch)
    );
    assert_eq!(sink.len(), 0, "the victim was not named as a holder");
}

/// PROPERTY: the network cannot tell this node what it holds.
///
/// An attacker who replays our own signed announce back at us must not be able to drive our local
/// provider set. The fixture uses OUR OWN valid signature, so only the self-attribution gate can
/// reject it — every authenticity check passes.
#[tokio::test]
async fn our_own_announce_replayed_back_at_us_is_ignored() {
    let us = TestPeer::new();
    let attacker = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(17);

    let rejected = ingress(&us.peer_id_hex)
        .accept(
            &sink,
            &attacker.peer_id_hex,
            &us.announce(1, vec![remove_delta(&id)]),
            NOW,
        )
        .await
        .expect_err("an announce attributed to this node itself must be ignored");

    assert_eq!(rejected, Rejected::SelfAttributed);
    assert_eq!(sink.len(), 0);
}

// ---------------------------------------------------------------------------------------------
// Ingress — replay + rate bounds
// ---------------------------------------------------------------------------------------------

/// PROPERTY: an announcement whose `seq` does not ADVANCE is dropped, so a captured frame cannot
/// resurrect a record its provider has since retracted.
///
/// The fixture replays the earlier ADD after the later REMOVE — the attack that actually matters.
/// A test that merely replayed the same frame twice could pass under an implementation that
/// deduplicates on bytes while still accepting an older seq.
#[tokio::test]
async fn a_replayed_older_seq_cannot_resurrect_a_retracted_record() {
    let holder = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(19);
    let ingress = ingress(&us.peer_id_hex);

    let add = holder.announce(5, vec![add_delta(&id)]);
    let retract = holder.announce(6, vec![remove_delta(&id)]);

    ingress
        .accept(&sink, &holder.peer_id_hex, &add, NOW)
        .await
        .expect("seq 5 is the provider's first announce");
    ingress
        .accept(&sink, &holder.peer_id_hex, &retract, NOW)
        .await
        .expect("seq 6 advances");
    assert!(!sink.holds(&id, &holder.peer_id_hex), "the retract applied");

    let rejected = ingress
        .accept(&sink, &holder.peer_id_hex, &add, NOW)
        .await
        .expect_err("replaying the older ADD must be dropped");

    assert_eq!(rejected, Rejected::StaleSeq { seq: 5, highest: 6 });
    assert!(
        !sink.holds(&id, &holder.peer_id_hex),
        "the retracted record must STAY retracted"
    );
}

/// PROPERTY: the per-provider announce budget bounds how often one holder may revise its holdings.
///
/// Pinned from both sides: the `MAX_ANNOUNCES_PER_PROVIDER`-th announcement in a window is accepted,
/// the next is refused. Each announcement carries ONE delta so the sender delta bucket cannot be the
/// thing that fires — otherwise this test would pass while the provider bucket did nothing.
#[tokio::test]
async fn the_per_provider_announce_budget_binds_at_its_stated_bound() {
    let holder = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let ingress = ingress(&us.peer_id_hex);

    for i in 0..MAX_ANNOUNCES_PER_PROVIDER {
        let seq = u64::from(i) + 1;
        ingress
            .accept(
                &sink,
                &holder.peer_id_hex,
                &holder.announce(seq, vec![add_delta(&content(u8::try_from(i).unwrap_or(0)))]),
                NOW,
            )
            .await
            .unwrap_or_else(|e| panic!("announce {seq} is at or under the bound, got {e:?}"));
    }

    let over = holder.announce(
        u64::from(MAX_ANNOUNCES_PER_PROVIDER) + 1,
        vec![add_delta(&content(250))],
    );
    assert_eq!(
        ingress
            .accept(&sink, &holder.peer_id_hex, &over, NOW)
            .await
            .expect_err("one announcement over the bound must be refused"),
        Rejected::RateLimited
    );

    // The budget is a WINDOW, not a lifetime cap — an honest long-lived holder must recover.
    ingress
        .accept(&sink, &holder.peer_id_hex, &over, NOW + RATE_WINDOW_SECS)
        .await
        .expect("the budget refills after the window elapses");
}

/// PROPERTY: the per-sender DELTA budget bounds total ingest work a neighbour can cause, INDEPENDENTLY
/// of the per-provider announce budget.
///
/// This is the guard that makes the two-bucket design non-redundant, so the fixture is built so the
/// provider bucket CANNOT be what fires: each maximal batch comes from a DIFFERENT provider, so every
/// provider bucket is at 1 of 10 while the sender's delta bucket fills. Batch size is taken from the
/// protocol limit (`HOLDINGS_MAX_CHANGES`), so the bound is expressed in the units the wire allows.
#[tokio::test]
async fn the_per_sender_delta_budget_binds_independently_of_the_provider_budget() {
    let relayer = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let ingress = ingress(&us.peer_id_hex);

    let maximal: Vec<_> = (0..HOLDINGS_MAX_CHANGES)
        .map(|i| add_delta(&content(u8::try_from(i % 251).unwrap_or(0))))
        .collect();
    let batches_at_bound = MAX_DELTAS_PER_SENDER / HOLDINGS_MAX_CHANGES as u32;

    for i in 0..batches_at_bound {
        let holder = TestPeer::new(); // a fresh provider each time — provider bucket stays at 1/10
        ingress
            .accept(
                &sink,
                &relayer.peer_id_hex,
                &holder.announce(1, maximal.clone()),
                NOW,
            )
            .await
            .unwrap_or_else(|e| panic!("maximal batch {i} is at or under the bound, got {e:?}"));
    }

    let fresh_holder = TestPeer::new();
    assert_eq!(
        ingress
            .accept(
                &sink,
                &relayer.peer_id_hex,
                &fresh_holder.announce(1, maximal.clone()),
                NOW,
            )
            .await
            .expect_err(
                "one maximal batch over the sender's delta budget must be refused even though \
                 this provider has never announced before"
            ),
        Rejected::RateLimited
    );

    // A DIFFERENT neighbour is unaffected — the budget is per sender, not global, so one abusive
    // neighbour cannot silence the rest of the network.
    let other_relayer = TestPeer::new();
    ingress
        .accept(
            &sink,
            &other_relayer.peer_id_hex,
            &fresh_holder.announce(1, maximal),
            NOW,
        )
        .await
        .expect("a different neighbour has its own budget");
}

/// PROPERTY: a rejected announcement charges NOTHING, so a flood of invalid frames cannot exhaust
/// the budget an honest announcement needs.
///
/// Nearest wrong implementation: charging the bucket before verifying — which turns the rate limiter
/// itself into the denial-of-service (one bad signature per honest announce silences a neighbour).
#[tokio::test]
async fn rejected_announcements_do_not_consume_the_budget() {
    let holder = TestPeer::new();
    let relayer = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let ingress = ingress(&us.peer_id_hex);
    let id = content(23);

    // Far more forgeries than either budget would allow, all from the same neighbour.
    let mut forged = holder.announce(1, vec![add_delta(&id)]);
    forged.signature[0] ^= 0xff;
    for _ in 0..(MAX_ANNOUNCES_PER_PROVIDER * 5) {
        assert!(matches!(
            ingress
                .accept(&sink, &relayer.peer_id_hex, &forged, NOW)
                .await,
            Err(Rejected::Unverified(_))
        ));
    }

    ingress
        .accept(
            &sink,
            &relayer.peer_id_hex,
            &holder.announce(1, vec![add_delta(&id)]),
            NOW,
        )
        .await
        .expect("an honest announcement still fits after a forgery flood");
    assert!(sink.holds(&id, &holder.peer_id_hex));
}

// ---------------------------------------------------------------------------------------------
// Egress composition — the broadcaster
// ---------------------------------------------------------------------------------------------

/// Records every announcement handed to the transport, in order.
#[derive(Default)]
struct RecordingTransport {
    sent: Mutex<Vec<HoldingsAnnounce>>,
}

#[async_trait::async_trait]
impl AnnounceTransport for RecordingTransport {
    async fn flood(&self, announce: &HoldingsAnnounce) -> usize {
        self.sent
            .lock()
            .expect("transport mutex")
            .push(announce.clone());
        1
    }
}

/// PROPERTY: a reconcile too large for one signed frame is SPLIT across frames with strictly
/// advancing `seq`, and every delta is flooded — never truncated.
///
/// This is the end-to-end version of the split property, and the two halves are load-bearing
/// together: a receiver drops any announcement whose seq does not advance, so a split that reused one
/// seq would have every frame after the first silently discarded — the same data loss as truncation,
/// just further downstream. The fixture is sized from the protocol limit
/// (`HOLDINGS_MAX_CHANGES + 1` gains) so it straddles a boundary by exactly one delta.
#[tokio::test]
async fn an_oversized_reconcile_floods_every_delta_across_advancing_seqs() {
    let transport = RecordingTransport::default();
    let broadcaster = HoldingsBroadcaster::new(
        TestPeer::new().signer,
        vec![GossipAddr {
            host: "::1".to_string(),
            port: 9_257,
        }],
        0,
    );

    let gained: Vec<_> = (0..=HOLDINGS_MAX_CHANGES)
        .map(|i| content(u8::try_from(i % 251).unwrap_or(0)))
        .collect();
    let frames = broadcaster
        .announce_change(&transport, &gained, &[], NOW)
        .await;

    assert_eq!(frames, 2, "257 deltas need two frames");
    let sent = transport.sent.lock().expect("transport mutex");
    assert_eq!(sent.len(), 2);
    assert!(
        sent[1].seq > sent[0].seq,
        "each frame must carry a strictly advancing seq, or a receiver drops all but the first: \
         got {} then {}",
        sent[0].seq,
        sent[1].seq
    );
    let total: usize = sent.iter().map(|a| a.changes.len()).sum();
    assert_eq!(
        total,
        gained.len(),
        "every delta must be flooded — a split must not lose one"
    );
}

/// PROPERTY: nothing changed means nothing is flooded (an idle node is silent on the wire).
#[tokio::test]
async fn an_empty_reconcile_floods_nothing() {
    let transport = RecordingTransport::default();
    let broadcaster = HoldingsBroadcaster::new(TestPeer::new().signer, Vec::new(), 7);

    assert_eq!(
        broadcaster.announce_change(&transport, &[], &[], NOW).await,
        0
    );
    assert!(transport.sent.lock().expect("mutex").is_empty());
}

// ---------------------------------------------------------------------------------------------
// Ingress — hex CASE MALLEABILITY (the gate-2 / gate-3 bypass)
// ---------------------------------------------------------------------------------------------
//
// `hex::decode` is case-INSENSITIVE and dig-gossip signs over the 32 DECODED bytes, so uppercasing
// any hex digit of `provider_peer_id` yields a still-valid signature for the same identity. Every
// comparison or map key that treats the field as an opaque `String` therefore has many spellings of
// one peer, and each spelling is a free bypass. These are exploit regressions, not unit tests of a
// helper: each replays a REAL signed announcement with its identity merely re-spelled.

/// Re-spell an announcement's `provider_peer_id` in upper case. The signature still verifies, because
/// it covers the decoded bytes rather than this text.
fn uppercase_provider(announce: &HoldingsAnnounce) -> HoldingsAnnounce {
    let mut respelled = announce.clone();
    respelled.provider_peer_id = respelled.provider_peer_id.to_uppercase();
    respelled
}

/// EXPLOIT (gate 2): our own announcement, replayed back at us with its identity uppercased, must
/// STILL be recognised as ours.
///
/// A `String ==` against a lowercase `self_peer_id` misses every case variant, letting the network
/// drive this node's own provider set — the exact thing gate 2 exists to prevent.
#[tokio::test]
async fn an_uppercased_replay_of_our_own_announce_is_still_self_attributed() {
    let us = TestPeer::new();
    let attacker = TestPeer::new();
    let sink = RecordingSink::default();
    let ours = us.announce(1, vec![add_delta(&content(31))]);

    let rejected = ingress(&us.peer_id_hex)
        .accept(
            &sink,
            &attacker.peer_id_hex,
            &uppercase_provider(&ours),
            NOW,
        )
        .await
        .expect_err("a case-respelled replay of OUR OWN announce must be self-attributed");

    assert_eq!(rejected, Rejected::SelfAttributed);
    assert_eq!(sink.len(), 0, "the network must not drive our own holdings");
}

/// EXPLOIT (gate 3): a case-respelled replay of an older announcement must NOT resurrect a record
/// its provider has since retracted.
///
/// Keying the replay watermark by hex SPELLING makes each variant a fresh provider seeded below its
/// own seq, so the stale frame is admitted; the Add path then normalises the id and writes to the
/// CANONICAL record. This also silently undoes the active-retract fix: a holder that evicted a
/// capsule is re-listed as a holder of content it cannot serve for the remaining TTL.
#[tokio::test]
async fn a_case_respelled_replay_cannot_resurrect_a_retracted_record() {
    let holder = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(37);
    let ingress = ingress(&us.peer_id_hex);

    let add = holder.announce(5, vec![add_delta(&id)]);
    ingress
        .accept(&sink, &holder.peer_id_hex, &add, NOW)
        .await
        .expect("seq 5 add");
    ingress
        .accept(
            &sink,
            &holder.peer_id_hex,
            &holder.announce(6, vec![remove_delta(&id)]),
            NOW,
        )
        .await
        .expect("seq 6 retract");
    assert!(!sink.holds(&id, &holder.peer_id_hex), "the retract applied");

    let rejected = ingress
        .accept(&sink, &holder.peer_id_hex, &uppercase_provider(&add), NOW)
        .await
        .expect_err("a case-respelled stale seq must still be stale");

    assert_eq!(rejected, Rejected::StaleSeq { seq: 5, highest: 6 });
    assert!(
        !sink.holds(&id, &holder.peer_id_hex),
        "a retracted record must STAY retracted under any spelling of the provider id"
    );
}

/// EXPLOIT (attribution): a case-respelled RETRACT must still resolve to the signer's own CANONICAL
/// record, and must not reach another holder's.
///
/// The truthful control holder must survive; and the attacker's own record — stored canonically by
/// the Add path — must be the one removed, which only happens if the remove argument is normalised.
#[tokio::test]
async fn a_case_respelled_retract_resolves_to_the_signers_canonical_record() {
    let attacker = TestPeer::new();
    let honest = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(41);
    sink.seed(&id, &honest.peer_id_hex);
    sink.seed(&id, &attacker.peer_id_hex);

    let applied = ingress(&us.peer_id_hex)
        .accept(
            &sink,
            &attacker.peer_id_hex,
            &uppercase_provider(&attacker.announce(1, vec![remove_delta(&id)])),
            NOW,
        )
        .await
        .expect("a validly signed retract is accepted");

    assert_eq!(
        applied.removed, 1,
        "the retract must resolve to the signer's CANONICAL record, not a case variant that \
         matches nothing"
    );
    assert!(
        sink.holds(&id, &honest.peer_id_hex),
        "the honest holder must survive a case-respelled retract"
    );
    assert!(!sink.holds(&id, &attacker.peer_id_hex));
}

/// PROPERTY: a provider id that is not canonical 64-hex is refused before anything else, so no
/// downstream comparison, map key or log ever sees attacker-shaped text.
///
/// The field is a `u16`-length-prefixed wire string, so it may carry tens of kilobytes of arbitrary
/// UTF-8 including newlines and terminal escapes.
#[tokio::test]
async fn a_non_canonical_provider_id_is_refused_outright() {
    let holder = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();

    let mut hostile = holder.announce(1, vec![add_delta(&content(53))]);
    hostile.provider_peer_id = "\n\u{1b}[31mFORGED LOG LINE ".repeat(64);

    let rejected = ingress(&us.peer_id_hex)
        .accept(&sink, &holder.peer_id_hex, &hostile, NOW)
        .await
        .expect_err("a non-hex provider id must be refused");

    assert!(
        matches!(rejected, Rejected::Unverified(_)),
        "expected a verification rejection, got {rejected:?}"
    );
    assert_eq!(sink.len(), 0);
}

// ---------------------------------------------------------------------------------------------
// Ingress — bounded FRESHNESS (a captured Remove must not replay forever)
// ---------------------------------------------------------------------------------------------

/// EXPLOIT (censorship across a restart): a captured retract, replayed at a node whose replay
/// watermark is empty, must NOT de-list an honest holder.
///
/// `HoldingsDelta::Remove` carries no expiry, so without a freshness check the ONLY barrier to an
/// indefinite replay is the in-memory per-provider watermark — which a fresh process does not have.
/// A victim restart (or a capacity eviction of its watermark) would therefore hand an attacker a free
/// de-listing of an honest peer: censorship, not the "bounded staleness" this module used to claim.
/// The fixture models the restart as a FRESH ingress; `announced_at` is signed, so the captured
/// frame's age cannot be rewritten.
#[tokio::test]
async fn a_captured_retract_replayed_after_a_restart_cannot_delist_an_honest_holder() {
    let honest = TestPeer::new();
    let attacker = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(43);

    // The honest holder's own signed retract, captured off the wire a day earlier.
    let captured = honest.announce(9, vec![remove_delta(&id)]);
    // ... and since then the honest holder is serving the capsule again.
    sink.seed(&id, &honest.peer_id_hex);

    // A FRESH ingress: the process restarted, so nothing remembers seq 9.
    let rejected = ingress(&us.peer_id_hex)
        .accept(&sink, &attacker.peer_id_hex, &captured, NOW + 86_400)
        .await
        .expect_err("a day-old captured retract must be refused on freshness alone");

    assert!(
        matches!(rejected, Rejected::Stale { .. }),
        "expected a freshness rejection, got {rejected:?}"
    );
    assert!(
        sink.holds(&id, &honest.peer_id_hex),
        "an honest holder must NOT be de-listable by replaying its own old retract"
    );
}

/// PROPERTY: freshness is bounded on BOTH sides, and AT the bound it passes.
///
/// A clock skew inside the window must not reject honest announcements; a future-dated frame must be
/// refused too, or an attacker could mint a retract that stays replayable long after it was captured.
#[tokio::test]
async fn the_freshness_window_binds_on_both_sides_of_its_bound() {
    let holder = TestPeer::new();
    let us = TestPeer::new();
    let window = IngressLimits::default().max_announce_age_secs;

    for (label, at_now) in [
        ("at the bound, frame in the past", NOW + window),
        ("at the bound, frame in the future", NOW - window),
    ] {
        let sink = RecordingSink::default();
        ingress(&us.peer_id_hex)
            .accept(
                &sink,
                &holder.peer_id_hex,
                &holder.announce(1, vec![add_delta(&content(47))]),
                at_now,
            )
            .await
            .unwrap_or_else(|e| panic!("{label} must be accepted (at-bound passes), got {e:?}"));
    }

    for (label, at_now) in [
        ("one second past the bound, in the past", NOW + window + 1),
        ("one second past the bound, in the future", NOW - window - 1),
    ] {
        let sink = RecordingSink::default();
        let outcome = ingress(&us.peer_id_hex)
            .accept(
                &sink,
                &holder.peer_id_hex,
                &holder.announce(1, vec![add_delta(&content(47))]),
                at_now,
            )
            .await;
        assert!(
            matches!(outcome, Err(Rejected::Stale { .. })),
            "{label} must be refused (one-over fails), got {outcome:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Ingress — rejections must not allocate tracking state
// ---------------------------------------------------------------------------------------------

/// PROPERTY: a REJECTED announcement leaves NO tracking state behind.
///
/// This replaces an earlier test that drove only the sender map through ACCEPTED announcements and
/// asserted `providers == 1` — a false green, because it never entered a reject path, so deleting the
/// provider-map eviction kept it passing. The leak this pins is the real one: an entry allocated
/// BEFORE the gates, on a path that returns early and therefore skips eviction, is unbounded growth
/// bought for ~180 wire bytes per entry.
#[tokio::test]
async fn rejected_announcements_allocate_no_tracking_state() {
    let us = TestPeer::new();
    let relayer = TestPeer::new();
    let sink = RecordingSink::default();
    let ingress = ingress(&us.peer_id_hex);

    // Exhaust the relaying sender's DELTA budget with maximal batches from a few real providers.
    // Every announcement after this is rejected on the sender bucket — which is decided AFTER the
    // provider entry would be allocated, so it is precisely the leak path.
    let maximal: Vec<_> = (0..HOLDINGS_MAX_CHANGES)
        .map(|i| add_delta(&content(u8::try_from(i % 251).unwrap_or(0))))
        .collect();
    let admitted = MAX_DELTAS_PER_SENDER / HOLDINGS_MAX_CHANGES as u32;
    for _ in 0..admitted {
        let holder = TestPeer::new();
        ingress
            .accept(
                &sink,
                &relayer.peer_id_hex,
                &holder.announce(1, maximal.clone()),
                NOW,
            )
            .await
            .expect("a maximal batch within the sender budget is admitted");
    }
    let (_, tracked_after_admits) = ingress.tracked_counts().await;

    // 50 announcements from 50 DISTINCT, freshly-minted providers — the attacker-chosen key space this
    // map must not follow — all refused on the exhausted sender budget.
    for i in 0..50u8 {
        let stranger = TestPeer::new();
        let refused = ingress
            .accept(
                &sink,
                &relayer.peer_id_hex,
                &stranger.announce(1, vec![add_delta(&content(i))]),
                NOW,
            )
            .await;
        assert!(
            matches!(refused, Err(Rejected::RateLimited)),
            "the sender budget is exhausted, so this must be refused; got {refused:?}"
        );
    }

    let (senders, providers) = ingress.tracked_counts().await;
    assert_eq!(
        providers, tracked_after_admits,
        "50 REJECTED announcements from 50 distinct providers must leave the tracked set UNCHANGED; \
         an entry allocated before the gates would show {} extra",
        50
    );
    assert_eq!(senders, 1, "one relaying sender throughout");
}

/// PROPERTY: the PROVIDER map is capacity-bounded, and the entry it drops at the bound is the
/// LEAST-RECENTLY-SEEN one.
///
/// This is the guard the previous round's `the_provider_tracking_map_is_capacity_bounded` claimed and
/// did not test: that test drove the SENDER map and closed on `providers == 1`, so deleting the
/// provider-side `evict_lru` kept it green. Two fixture choices make this one able to see the guard:
///
/// - **A reachable cap.** [`IngressLimits::tracked_providers`] is parameterised, so the bound is
///   crossed with four P-256 identities instead of 8,193. A bound that can only be reached by an
///   unaffordable fixture is a bound that never gets tested.
/// - **A second observable besides the count.** A count alone cannot distinguish LRU eviction from
///   evicting an arbitrary entry — or from evicting the entry just admitted. Eviction is therefore
///   observed through its CONSEQUENCE: losing an entry loses that provider's replay watermark, so the
///   victim's already-applied `seq` becomes admissible again while a retained provider's stays
///   `StaleSeq`. The same replay is asserted to be REFUSED before the bound is crossed, so the later
///   admission is attributable to the eviction and to nothing else.
///
/// A rejected announcement from a fifth, never-seen provider sits in the middle of the fixture: it
/// must neither grow the map nor evict anybody, which is the composition of this bound with the
/// allocate-nothing-on-reject rule above.
#[tokio::test]
async fn the_provider_map_evicts_the_least_recently_seen_at_its_capacity() {
    const CAP: usize = 3;
    let us = TestPeer::new();
    let relayer = TestPeer::new();
    let sink = RecordingSink::default();
    let ingress = HoldingsIngress::with_limits(
        us.peer_id_hex.clone(),
        IngressLimits {
            tracked_providers: CAP,
            ..IngressLimits::default()
        },
    );

    // Four holders, each seen at a distinct second so the least-recently-seen order is unambiguous.
    // All four stamps stay well inside MAX_ANNOUNCE_AGE_SECS of the announcements' `announced_at`.
    let holders: Vec<TestPeer> = (0..4).map(|_| TestPeer::new()).collect();
    let seen_at = |i: usize| NOW + i as u64;
    let admit = |i: usize| {
        let announce = holders[i].announce(7, vec![add_delta(&content(70 + i as u8))]);
        let ingress = &ingress;
        let sink = &sink;
        let sender = &relayer.peer_id_hex;
        let provider = &holders[i].peer_id_hex;
        async move {
            ingress
                .accept(sink, sender, &announce, seen_at(i))
                .await
                .unwrap_or_else(|e| panic!("holder {i} ({provider}) must be admitted, got {e:?}"));
        }
    };
    // A replay of holder `i`'s seq-7 announcement, judged at the clock of the last admitted holder.
    let replay = |i: usize, at: u64| {
        let announce = holders[i].announce(7, vec![add_delta(&content(70 + i as u8))]);
        let ingress = &ingress;
        let sink = &sink;
        let sender = &relayer.peer_id_hex;
        async move { ingress.accept(sink, sender, &announce, at).await }
    };

    for i in 0..CAP {
        admit(i).await;
    }
    let (_, at_cap) = ingress.tracked_counts().await;
    assert_eq!(
        at_cap, CAP,
        "exactly at the capacity nothing may be evicted — a bound tested only from above cannot \
         show it is the RIGHT bound"
    );
    assert_eq!(
        replay(0, seen_at(CAP)).await,
        Err(Rejected::StaleSeq {
            seq: 7,
            highest: 7
        }),
        "before the bound is crossed the oldest provider still holds its watermark; without this the \
         admission asserted below would not be attributable to eviction"
    );

    // A rejected announcement in the mix: a never-seen provider whose frame is too old to act on. It
    // is judged at the live clock, so it cannot disturb the eviction order it must not affect.
    let stranger = TestPeer::new();
    let stale = stranger.announce_at(
        1,
        NOW - MAX_ANNOUNCE_AGE_SECS - 1,
        vec![add_delta(&content(99))],
    );
    assert!(
        matches!(
            ingress
                .accept(&sink, &relayer.peer_id_hex, &stale, seen_at(CAP))
                .await,
            Err(Rejected::Stale { .. })
        ),
        "the fixture's rejected frame must be rejected on FRESHNESS, not on the capacity bound"
    );
    let (_, after_reject) = ingress.tracked_counts().await;
    assert_eq!(
        after_reject, CAP,
        "a rejected announcement must neither allocate an entry nor evict one"
    );

    // One over the bound.
    admit(CAP).await;
    let last = seen_at(CAP);
    let (_, over_cap) = ingress.tracked_counts().await;
    assert_eq!(
        over_cap,
        CAP,
        "admitting a {n}th distinct provider must leave the map at its capacity",
        n = CAP + 1
    );
    // The retained provider is asserted FIRST: a readmitted provider evicts a new victim, so probing
    // the evicted one first would destroy the very watermark the next assertion reads.
    assert_eq!(
        replay(1, last).await,
        Err(Rejected::StaleSeq {
            seq: 7,
            highest: 7
        }),
        "a provider that was NOT the least-recently-seen must keep its watermark — otherwise the map \
         is being cleared, or the wrong victim chosen, rather than evicted least-recently-seen first"
    );
    assert!(
        replay(0, last).await.is_ok(),
        "the LEAST-recently-seen provider is the one evicted, so its watermark is gone and its own \
         seq-7 frame is admissible again"
    );
}

/// PROPERTY: the SENDER map is capacity-bounded, and the entry it drops at the bound is the
/// LEAST-RECENTLY-SEEN one.
///
/// The sender half of `SPEC.md` §19.3a's "capacity-bounded (1,024 senders, 8,192 providers) with
/// least-recently-seen eviction" was, until this test, an untested claim: deleting
/// `evict_lru(&mut self.senders, …)` left the whole suite green. It is a real bound, not bookkeeping
/// — a `peer_id` is `SHA-256(NodeCert SPKI)` and therefore self-minted, so connect → announce →
/// disconnect churn offers an unbounded key space and nothing else ever removes a sender entry.
///
/// The fixture mirrors the provider-side test's two disciplines, because a count alone cannot tell
/// LRU eviction from evicting an arbitrary entry:
///
/// - **A reachable cap.** [`IngressLimits::tracked_senders`] is parameterised, so the bound is
///   crossed with four transport identities instead of 1,025.
/// - **A second observable besides the count.** Eviction is read through its CONSEQUENCE: a sender
///   entry IS that sender's delta budget, so losing the entry restores an exhausted sender's ability
///   to relay. Every sender is driven to exhaustion first, the same relay is asserted REFUSED before
///   the bound is crossed, and a RETAINED sender is probed before the evicted one — so the final
///   admission is attributable to eviction of the least-recently-seen entry and to nothing else.
///
/// A too-old frame from a never-seen fifth sender sits in the middle: it must neither allocate a
/// sender entry nor evict one, composing this bound with the allocate-nothing-on-reject rule.
#[tokio::test]
async fn the_sender_map_evicts_the_least_recently_seen_at_its_capacity() {
    const CAP: usize = 3;
    /// Deltas one sender may relay per window — small enough that two relays exhaust it.
    const BUDGET: u32 = 2;

    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let ingress = HoldingsIngress::with_limits(
        us.peer_id_hex.clone(),
        IngressLimits {
            tracked_senders: CAP,
            deltas_per_sender: BUDGET,
            ..IngressLimits::default()
        },
    );

    // Four relaying transports, each last seen at a distinct second so the least-recently-seen order
    // is unambiguous. All stamps stay well inside both RATE_WINDOW_SECS and MAX_ANNOUNCE_AGE_SECS.
    let relays: Vec<TestPeer> = (0..=CAP).map(|_| TestPeer::new()).collect();
    let seen_at = |i: usize| NOW + i as u64;

    // One relay through transport `i`, carrying a single delta from a FRESHLY minted provider — so
    // every provider-side gate passes and the only budget in play is the sender's.
    let relay = |i: usize, seed: u8, at: u64| {
        let announce = TestPeer::new().announce(1, vec![add_delta(&content(seed))]);
        let ingress = &ingress;
        let sink = &sink;
        let sender = &relays[i].peer_id_hex;
        async move { ingress.accept(sink, sender, &announce, at).await }
    };

    // Fill the map to capacity, exhausting each sender's budget as we go.
    for i in 0..CAP {
        for d in 0..BUDGET {
            let seed = 10 + (i as u32 * BUDGET + d) as u8;
            relay(i, seed, seen_at(i))
                .await
                .unwrap_or_else(|e| panic!("sender {i} relay {d} must be admitted, got {e:?}"));
        }
    }
    let (at_cap, _) = ingress.tracked_counts().await;
    assert_eq!(
        at_cap, CAP,
        "exactly at the capacity nothing may be evicted — a bound tested only from above cannot \
         show it is the RIGHT bound"
    );
    assert_eq!(
        relay(0, 90, seen_at(CAP)).await,
        Err(Rejected::RateLimited),
        "before the bound is crossed the oldest sender still holds its exhausted budget; without \
         this the admission asserted below would not be attributable to eviction"
    );

    // A rejected frame in the mix, from a transport this ingress has never seen.
    let stranger_sender = TestPeer::new();
    let stale = TestPeer::new().announce_at(
        1,
        NOW - MAX_ANNOUNCE_AGE_SECS - 1,
        vec![add_delta(&content(91))],
    );
    assert!(
        matches!(
            ingress
                .accept(&sink, &stranger_sender.peer_id_hex, &stale, seen_at(CAP))
                .await,
            Err(Rejected::Stale { .. })
        ),
        "the fixture's rejected frame must be rejected on FRESHNESS, not on the capacity bound"
    );
    let (after_reject, _) = ingress.tracked_counts().await;
    assert_eq!(
        after_reject, CAP,
        "a rejected announcement must neither allocate a sender entry nor evict one"
    );

    // One over the bound.
    let last = seen_at(CAP);
    relay(CAP, 92, last).await.unwrap_or_else(|e| {
        panic!(
            "a {n}th distinct sender must be admitted, got {e:?}",
            n = CAP + 1
        )
    });
    let (over_cap, _) = ingress.tracked_counts().await;
    assert_eq!(
        over_cap,
        CAP,
        "admitting a {n}th distinct sender must leave the map at its capacity",
        n = CAP + 1
    );

    // The retained sender is asserted FIRST: readmitting the evicted one evicts a new victim, which
    // would destroy the very budget the other assertion reads.
    assert_eq!(
        relay(1, 93, last).await,
        Err(Rejected::RateLimited),
        "a sender that was NOT the least-recently-seen must keep its exhausted budget — otherwise \
         the map is being cleared, or the wrong victim chosen, rather than evicted \
         least-recently-seen first"
    );
    assert!(
        relay(0, 94, last).await.is_ok(),
        "the LEAST-recently-seen sender is the one evicted, so its budget is gone with its entry \
         and it may relay again"
    );
}

// =============================================================================================
// The three guards the round-2 defect-revert probe found UNVERIFIED
// =============================================================================================

/// Captures everything logged inside a scope, so an assertion can read exactly what an operator
/// tailing the node log would see.
#[derive(Clone, Default)]
struct CaptureBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CaptureBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture mutex").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureBuffer {
    type Writer = CaptureBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// PROPERTY (item 6): no peer-supplied byte ever reaches the log, on ANY path.
///
/// `provider_peer_id` is a `u16`-length-prefixed wire string, so a hostile peer may put tens of
/// kilobytes of arbitrary UTF-8 there — newlines that forge whole log lines, ANSI escapes that drive
/// an operator's terminal. This is asserted against the REAL ingest loop's REAL emitted records
/// (captured through a `tracing` subscriber), not against a return value, because the defect is in
/// what the loop *emits*: keeping the record at `debug` bounds log VOLUME and says nothing about
/// CONTENT, so a level-based rationale cannot substitute for not emitting the field.
#[tokio::test]
async fn no_peer_supplied_bytes_ever_reach_the_log() {
    let holder = TestPeer::new();
    let us = TestPeer::new();

    // A forged log line, a terminal escape, and enough length to be obvious in a diff.
    let hostile = "\n\u{1b}[2J\u{1b}[31mnode: CRITICAL forged line ".repeat(40);
    let mut announce = holder.announce(1, vec![add_delta(&content(59))]);
    announce.provider_peer_id = hostile.clone();

    let (tx, rx) = tokio::sync::broadcast::channel(8);
    tx.send((
        dig_gossip::PeerId::from([0x33u8; 32]),
        frame_holdings_announce(&announce),
    ))
    .expect("the receiver is live");
    drop(tx); // closes the channel so `run_holdings_ingest` returns after draining

    let buffer = CaptureBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(buffer.clone())
        .finish();
    {
        let _guard = tracing::subscriber::set_default(subscriber);
        run_holdings_ingest(
            rx,
            Arc::new(HoldingsIngress::new(us.peer_id_hex.clone())),
            local_dht_service(9_401),
        )
        .await;
    }
    let logged =
        String::from_utf8_lossy(&buffer.0.lock().expect("capture mutex").clone()).into_owned();

    assert!(
        !logged.contains("forged line"),
        "the peer-supplied provider id must NEVER be logged; captured:\n{logged}"
    );
    assert!(
        !logged.contains('\u{1b}'),
        "no terminal escape from a peer-supplied field may reach the log; captured:\n{logged}"
    );
    assert!(
        logged.contains("<malformed>"),
        "the rejection should still be observable, just without attacker-shaped text; captured:\n{logged}"
    );
}

/// PROPERTY (end to end): an announcement declaring far more addresses than the cap is still ACCEPTED,
/// and the record it produces is bounded — an oversized list is trimmed, never a rejection.
///
/// Deliberately NOT the guard test for the cap's placement. `ProviderRecord::new` truncates as well, so
/// this assertion stays green with `bounded_dht_addresses`' `take` deleted; it can only see the stored
/// record, and both placements store the same one. The placement — mapping at most the cap, so the
/// allocation and not merely the record is bounded — is pinned by the colocated unit test
/// `the_address_cap_is_applied_where_the_mapping_happens`, which observes the mapper's own output.
///
/// The sink here records the WHOLE `ProviderRecord`: the narrower `(content_key, provider)` double used
/// elsewhere physically cannot express an address-count lie.
#[tokio::test]
async fn an_oversized_address_list_still_yields_a_bounded_record() {
    let holder = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingRecords::default();
    let cap = dig_dht::MAX_ADDRESSES_PER_RECORD;

    let declared = cap * 4;
    let addresses: Vec<_> = (0..declared)
        .map(|i| dig_gossip::CandidateAddr {
            host: format!("::{i:x}"),
            port: 9_257,
        })
        .collect();
    let announce = holder.announce(
        1,
        vec![HoldingsDelta::Add {
            content_key: *content(61).to_key().as_bytes(),
            addresses,
            expires_at: NOW + 3_600,
        }],
    );

    HoldingsIngress::new(us.peer_id_hex.clone())
        .accept(&sink, &holder.peer_id_hex, &announce, NOW)
        .await
        .expect("a validly signed announcement is accepted");

    let records = sink.records.lock().expect("sink mutex");
    assert_eq!(records.len(), 1);
    assert!(
        records[0].addresses.len() <= cap,
        "an attacker-declared address count must be truncated to MAX_ADDRESSES_PER_RECORD ({cap}) \
         before the list is mapped; got {} from {declared} declared",
        records[0].addresses.len()
    );
}

/// PROPERTY (watermark lifetime): a rate window elapsing must NOT reset the replay watermark.
///
/// Replay protection is not a rate limit. Folding the two together means simply waiting out one
/// 60-second window makes every captured frame replayable again — so a retracted record can be
/// resurrected on a timer. The fixture waits exactly one window (still well inside the freshness
/// bound, so that gate cannot be what rejects the replay — otherwise this test would pass for the
/// wrong reason).
#[tokio::test]
async fn a_rate_window_elapsing_does_not_reset_the_replay_watermark() {
    let holder = TestPeer::new();
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    let id = content(67);
    let ingress = ingress(&us.peer_id_hex);

    let add = holder.announce(5, vec![add_delta(&id)]);
    ingress
        .accept(&sink, &holder.peer_id_hex, &add, NOW)
        .await
        .expect("seq 5 add");
    ingress
        .accept(
            &sink,
            &holder.peer_id_hex,
            &holder.announce(6, vec![remove_delta(&id)]),
            NOW,
        )
        .await
        .expect("seq 6 retract");

    // One full rate window later — inside MAX_ANNOUNCE_AGE_SECS, so freshness still accepts it.
    let later = NOW + RATE_WINDOW_SECS;
    assert!(
        RATE_WINDOW_SECS < IngressLimits::default().max_announce_age_secs,
        "the fixture is only meaningful while a window is shorter than the freshness bound"
    );
    let rejected = ingress
        .accept(&sink, &holder.peer_id_hex, &add, later)
        .await
        .expect_err("the watermark must outlive the rate window");

    assert_eq!(rejected, Rejected::StaleSeq { seq: 5, highest: 6 });
    assert!(
        !sink.holds(&id, &holder.peer_id_hex),
        "waiting out one rate window must not make a retracted record resurrectable"
    );
}
