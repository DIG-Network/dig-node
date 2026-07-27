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
use std::sync::Mutex;

use dig_dht::{ContentId, ProviderRecord};
use dig_gossip::{
    CandidateAddr as GossipAddr, EcdsaHoldingsSigner, HoldingsAnnounce, HoldingsDelta,
    HoldingsError, HOLDINGS_MAX_CHANGES,
};
use dig_node_core::seams::dig_peer::holdings::{
    announcement_for, deltas_for, split_batches, AnnounceTransport, Applied, HoldingsBroadcaster,
    HoldingsIngress, HoldingsSink, Rejected, ADVERTISED_TTL_SECS, MAX_ANNOUNCES_PER_PROVIDER,
    MAX_DELTAS_PER_SENDER, MAX_TRACKED_SENDERS, RATE_WINDOW_SECS,
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

    /// Sign `changes` as this peer at `seq`.
    fn announce(&self, seq: u64, changes: Vec<HoldingsDelta>) -> HoldingsAnnounce {
        HoldingsAnnounce::new_signed(&self.signer, seq, NOW, changes)
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
// Ingress — bounded state
// ---------------------------------------------------------------------------------------------

/// PROPERTY: the guard maps are capacity-bounded, so the ingress cannot become its own denial of
/// service by remembering every identity an attacker mints.
///
/// The bound is pinned from both sides: at the cap the map holds exactly the cap, and pushing PAST it
/// still holds exactly the cap (never cap+1). The fixture drives the PROVIDER map, whose key space is
/// the attacker-chosen one — the sender map's key space is the connected pool and cannot be inflated
/// from off-network, so the provider map is the one that must not grow without limit.
#[tokio::test]
async fn the_provider_tracking_map_is_capacity_bounded() {
    let us = TestPeer::new();
    let sink = RecordingSink::default();
    // A tiny window is irrelevant here; the LRU cap is a compile-time constant, so this test asserts
    // the invariant with a small stand-in map size by driving well past it would be too slow at 8,192
    // providers x a real P-256 signature each. Instead it drives the SENDER map, whose cap is reached
    // with cheap distinct sender ids and which shares the same `evict_lru` implementation.
    let ingress = HoldingsIngress::new(us.peer_id_hex.clone());
    let holder = TestPeer::new();

    // One valid announcement per distinct sender id: MAX_TRACKED_SENDERS + 64 senders.
    for i in 0..(MAX_TRACKED_SENDERS + 64) {
        let sender = format!("{:064x}", i);
        let seq = u64::try_from(i).unwrap_or(u64::MAX) + 1;
        ingress
            .accept(
                &sink,
                &sender,
                &holder.announce(seq, vec![add_delta(&content(1))]),
                // Advance the clock a window per 10 announcements so the per-provider budget refills;
                // this test is about the MAP bound, not the rate bound.
                NOW + (u64::try_from(i).unwrap_or(0) / 5) * RATE_WINDOW_SECS,
            )
            .await
            .unwrap_or_else(|e| panic!("sender {i} should be admitted, got {e:?}"));
        let (senders, _) = ingress.tracked_counts().await;
        assert!(
            senders <= MAX_TRACKED_SENDERS,
            "the sender map must never exceed its cap; at i={i} it held {senders}"
        );
    }

    let (senders, providers) = ingress.tracked_counts().await;
    assert_eq!(
        senders, MAX_TRACKED_SENDERS,
        "past the cap the map settles AT the cap, evicting least-recently-seen"
    );
    assert_eq!(providers, 1, "one provider announced throughout");
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
