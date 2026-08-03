//! Real-time holdings announce (dig-gossip **opcode 222**) — the flywheel's freshness signal.
//!
//! The content-replication flywheel is `read → cache → announce → others discover you → they read
//! from you → …`. Its *durable* half already exists in [`dht`](super::dht): every inventory change
//! reconciles the node's dig-dht provider records (`announce_provider` on gain, withdraw on loss)
//! and `find_providers` locates holders. That half is correct but **slow to converge** — a new
//! holder is only as discoverable as the last DHT PUT reached, and a departed holder lingers until
//! its record's TTL expires.
//!
//! This module adds the *real-time, authenticated* half:
//!
//! - **Egress** ([`announcement_for`]) — an inventory delta becomes a signed [`HoldingsAnnounce`]
//!   flooded to every peer, so holder-set changes propagate in seconds rather than at TTL scale.
//! - **Ingress** ([`HoldingsIngress`]) — an inbound announce is verified, rate-limited, and folded
//!   into the local provider set via `ingest_verified_provider` / `remove_provider_record`.
//!
//! # Why the ingress is the dangerous half
//!
//! dig-dht is crypto-free by design (its SPEC §15): `ingest_verified_provider` is the **sole
//! sanctioned bypass** of the DHT's own mTLS self-announce identity check, and
//! `remove_provider_record` takes `(content_key, provider_peer_id)` as two independent strings with
//! nothing binding them. Every authentication, attribution and rate guard therefore lives HERE.
//! The threat classes this module is built against, each guarded over the CLASS and not one
//! attacker action:
//!
//! | Class | Guard |
//! |---|---|
//! | **Forged attribution** — naming another peer as a holder, or as *not* a holder | An announce's provider identity is [`HoldingsAnnounce::provider_peer_id`], which `verify_holdings_announce` proves equals `SHA-256(provider_spki)` and which signed the batch. [`HoldingsIngress::accept`] takes **no** caller-supplied provider id, so no code path can name a peer the signature does not attribute. |
//! | **Identity re-spelling** — the same signer wearing many names | Hex is case-INSENSITIVE and the signature covers the DECODED bytes, so one identity has many spellings that all verify. [`HoldingsIngress::accept`] canonicalizes ONCE, up front, and every later comparison, map key and sink argument uses only that value — otherwise each spelling is a fresh provider with no replay watermark, and a lowercase self-id comparison misses all of them. |
//! | **Amplification** — one cheap inbound message causing outbound work | The ingress performs **zero egress**: it never re-broadcasts, dials, probes, or fetches. Its whole cost is bounded local map work. |
//! | **Flood / Sybil eviction** — evicting an honest holder from a full provider set | Two token buckets at ONE chokepoint ([`IngressLimits`]): announcements per *provider* and deltas per *transport sender*. They are keyed differently on purpose — see [`MAX_DELTAS_PER_SENDER`] for why each covers the other's weakness. A rejected announcement charges neither, so the limiter cannot itself be turned into the denial of service. |
//! | **Replay** — resurrecting a retracted record, or undoing a newer announce | TWO independent barriers, because either alone is escapable: a per-provider monotonic [`HoldingsAnnounce::seq`] watermark (keyed by the CANONICAL id), and a bounded-freshness check on the signed `announced_at` ([`MAX_ANNOUNCE_AGE_SECS`]). The watermark is in-memory, so a restart or a capacity eviction clears it; freshness holds regardless of watermark state, which matters most for a `Remove` — it carries no expiry of its own. |
//! | **Self-poisoning** — replaying our own announce back at us | An announce attributed to this node's own `peer_id` is dropped; only this node decides what it holds. |
//! | **Unbounded state** — the guard maps themselves becoming the DoS | A REJECTED announcement allocates nothing at all: [`IngressState::admit`] decides every gate against borrowed state and inserts only after all of them pass, so no reject path can grow a map. Admitted entries are then capacity-bounded with LRU eviction ([`MAX_TRACKED_SENDERS`], [`MAX_TRACKED_PROVIDERS`]). |
//!
//! A false claim is cheap to disprove and costs the liar, not the reader: a bogus provider record
//! only ever yields a *dial that fails* or a `dig.getAvailability` that answers "no", after which
//! the peer-selector deranks the liar. The liar paid a signature and a flood to buy one failed dial.

use std::collections::HashMap;
use std::sync::Arc;

use dig_dht::{CandidateAddr as DhtAddr, ContentId, Key, PeerId, ProviderRecord};
use dig_gossip::{
    verify_holdings_announce, CandidateAddr as GossipAddr, EcdsaHoldingsSigner, HoldingsAnnounce,
    HoldingsDelta, HoldingsError, HoldingsSigner, HOLDINGS_MAX_CHANGES,
};

/// How long an `Add` advertisement claims to stay valid, in seconds.
///
/// Chosen to match dig-dht's own provider TTL band rather than a round number: dig-dht clamps an
/// ingested record to `min(record.expires_at, now + provider_ttl)`, so claiming *longer* than the
/// DHT's TTL is silently truncated and claiming *shorter* under-advertises a holder that is in fact
/// still serving. One hour sits inside every current provider TTL, so the clamp is a no-op and the
/// advertised lifetime is the one the announcer actually meant.
///
/// COUPLING — ENFORCED, not merely described (#1722). Two relations bind this value to dig-dht, and
/// `tests/holdings_ttl_coupling.rs` fails if either breaks:
/// - `ADVERTISED_TTL_SECS <= `[`dig_dht::DhtConfig::provider_ttl`] (default 2h) — exceeding it makes
///   every claim silently clamped, so the announcer's intent is lost.
/// - [`dig_dht::DhtConfig::republish_interval`]` <= ADVERTISED_TTL_SECS` (default 1h) — a record that
///   expires before the holder re-announces drops the holder out of discovery until it does.
///
/// The second currently holds EXACTLY, with zero margin: dig-dht republishes hourly and this claims
/// one hour. That is measured, not designed; the test records it so neither side can drift silently.
/// It also stays `<=` the smallest `provider_ttl` any receiving node configures — which is why the
/// value is not simply raised to 2h to buy refresh margin.
pub const ADVERTISED_TTL_SECS: u64 = 3_600;

/// Announcements one **provider** may have applied per [`RATE_WINDOW_SECS`].
///
/// The value dig-dht's SPEC §14 delegates to the embedding node (~10 announces/holder/min). Keyed by
/// provider because that is what the number means semantically: how often a holder may revise the
/// content it advertises. An honest node announces on an inventory *change*; ten changes a minute is
/// already far above steady state.
pub const MAX_ANNOUNCES_PER_PROVIDER: u32 = 10;

/// Deltas one **transport sender** may cause per [`RATE_WINDOW_SECS`].
///
/// The two buckets are deliberately keyed differently, because each covers the other's weakness:
///
/// - The provider bucket is semantically right but its key space is attacker-minted, so its map must
///   be LRU-bounded ([`MAX_TRACKED_PROVIDERS`]) — and an attacker who overflows that map can evict
///   its own bucket and refill it. Alone, it is bypassable.
/// - This bucket is keyed by the gossip sender, whose key space is the connected pool — a set the
///   attacker cannot inflate from off-network. Alone it is coarse (it cannot distinguish one chatty
///   holder from a hundred quiet ones), but it is **not bypassable**, so it is the backstop that
///   caps total ingest work per neighbour no matter what the provider bucket lets through.
///
/// The value is `4 × `[`HOLDINGS_MAX_CHANGES`] — a neighbour may relay four maximal signed batches,
/// or ~1,024 single-delta announcements, per window. It is deliberately far BELOW what the provider
/// bucket alone permits (`10 × 256 = 2,560` deltas per provider, times unbounded providers), which
/// is what makes it load-bearing rather than a restatement of the other bound.
pub const MAX_DELTAS_PER_SENDER: u32 = 4 * HOLDINGS_MAX_CHANGES as u32;

/// The token-bucket refill window, in seconds.
pub const RATE_WINDOW_SECS: u64 = 60;

/// How far `announced_at` may be from the receiver's clock, in either direction, before the
/// announcement is refused as stale.
///
/// This bound is what makes a captured announcement stop being useful, and it is required rather
/// than merely defensive: a `Remove` delta carries NO expiry of its own, so without it the only
/// barrier to replaying a captured retract forever is the in-memory per-provider `seq` watermark —
/// which a restart clears and a capacity eviction drops. That would let anyone de-list an honest
/// holder by replaying the holder's own old retract at a freshly started peer, which is censorship,
/// not staleness. Persisting the watermark is complementary (#1477) but is NOT a substitute: the
/// signature binds WHO announced, and only this comparison binds WHEN.
///
/// Five minutes is generous enough to absorb ordinary NTP skew and flood propagation delay while
/// keeping a captured frame useful for minutes rather than indefinitely. It is symmetric because a
/// future-dated frame is the same attack: an attacker who could post-date `announced_at` would mint a
/// retract that stays replayable long after capture.
pub const MAX_ANNOUNCE_AGE_SECS: u64 = 300;

/// Transport senders tracked before the least-recently-seen is evicted.
///
/// The key is a peer this node holds a live mTLS link to, but "headroom over a realistic connected
/// pool" is the wrong reading of this number: it is a HARD BOUND on unbounded growth. A `peer_id` is
/// `SHA-256(NodeCert SPKI)` — self-minted, costing one key pair — and an entry is never removed by
/// disconnection, so the key space this map follows is the set of transports that have EVER relayed
/// an accepted announcement, which connect → announce → disconnect churn grows without limit. The
/// eviction, not the pool size, is what keeps the map finite.
pub const MAX_TRACKED_SENDERS: usize = 1_024;

/// Providers tracked (latest `seq` + announce bucket) before the least-recently-seen is evicted.
///
/// Bounded because the provider id inside an announce is attacker-chosen.
///
/// Losing an entry to eviction costs a provider its replay watermark. That is NOT harmless on its own
/// — an earlier version of this comment claimed it meant "bounded staleness, never cross-peer
/// censorship", which was wrong: the signature binds WHO announced but not WHEN, so replaying a
/// holder's own captured `Remove` (which carries no expiry) at a peer with no watermark de-lists an
/// honest holder. [`MAX_ANNOUNCE_AGE_SECS`] is what actually closes that class, independently of
/// watermark state. Losing an announce bucket is separately backstopped by
/// [`MAX_DELTAS_PER_SENDER`], which cannot be evicted out from under an attacker.
pub const MAX_TRACKED_PROVIDERS: usize = 8_192;

// ---------------------------------------------------------------------------------------------
// Egress — turning an inventory change into a signed announcement
// ---------------------------------------------------------------------------------------------

/// Build this node's holdings signer from its persistent mTLS identity.
///
/// The wire fixes the signing key: `provider_peer_id` is `SHA-256(provider_spki)`, and the node's
/// advertised `peer_id` is `SHA-256(NodeCert SPKI DER)` (§5.2). Signing with anything other than the
/// [`NodeCert`](dig_nat::NodeCert) leaf would therefore announce holdings under an identity no peer
/// can dial. The leaf is ECDSA-P256 (dig-tls mints it with `PKCS_ECDSA_P256_SHA256`), which is
/// exactly what `verify_holdings_announce` requires.
///
/// # Errors
///
/// A message describing why the leaf private key could not be loaded as an ECDSA-P256 key pair —
/// the only way this fails is a NodeCert whose leaf is not P-256, which no dig-tls version mints.
pub fn signer_from_node_cert(cert: &dig_nat::NodeCert) -> Result<EcdsaHoldingsSigner, String> {
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    let key_der = cert.rustls_private_key();
    let rng = ring::rand::SystemRandom::new();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_der.secret_der(), &rng)
            .map_err(|e| format!("node cert leaf key is not a usable ECDSA-P256 key pair: {e}"))?;
    Ok(EcdsaHoldingsSigner::new(key_pair, cert.spki_der().to_vec()))
}

/// Build the signed [`HoldingsAnnounce`] for one inventory delta, or `None` when nothing changed.
///
/// `gained` content ids become `Add` deltas advertising `addresses` until
/// `now + `[`ADVERTISED_TTL_SECS`]; `lost` ids become `Remove` deltas. The announcement is signed
/// by `signer` — necessarily the node's own TLS leaf key, since the wire's `provider_peer_id` is
/// derived from that key's SPKI — so the flood is self-attributing.
///
/// `seq` MUST strictly increase across a node's announcements: a receiver drops any announce whose
/// seq does not advance (see [`HoldingsIngress::accept`]), so a repeated seq silently stops
/// propagating.
///
/// # Errors
///
/// [`HoldingsError::TooManyChanges`] when the combined delta count exceeds
/// [`HOLDINGS_MAX_CHANGES`]. The batch is refused rather than truncated, so a caller can never
/// silently drop a retract — split with [`split_batches`] before calling.
pub fn announcement_for<S: HoldingsSigner + ?Sized>(
    signer: &S,
    seq: u64,
    now: u64,
    gained: &[ContentId],
    lost: &[ContentId],
    addresses: &[GossipAddr],
) -> Result<Option<HoldingsAnnounce>, HoldingsError> {
    let changes = deltas_for(now, gained, lost, addresses);
    if changes.is_empty() {
        return Ok(None);
    }
    HoldingsAnnounce::new_signed(signer, seq, now, changes).map(Some)
}

/// The `Add`/`Remove` delta batch for an inventory change, adds first.
///
/// Kept separate from [`announcement_for`] so the wire encoding of a delta set is unit-testable
/// without a signing key.
#[must_use]
pub fn deltas_for(
    now: u64,
    gained: &[ContentId],
    lost: &[ContentId],
    addresses: &[GossipAddr],
) -> Vec<HoldingsDelta> {
    let expires_at = now.saturating_add(ADVERTISED_TTL_SECS);
    let adds = gained.iter().map(|id| HoldingsDelta::Add {
        content_key: *id.to_key().as_bytes(),
        addresses: addresses.to_vec(),
        expires_at,
    });
    let removes = lost.iter().map(|id| HoldingsDelta::Remove {
        content_key: *id.to_key().as_bytes(),
    });
    adds.chain(removes).collect()
}

/// Split a delta set into batches each within [`HOLDINGS_MAX_CHANGES`], preserving order.
///
/// A node that caches or drops many capsules at once (a bulk warm, a cache clear) produces more
/// deltas than one signed frame may carry. Splitting keeps every delta — the alternative,
/// truncation, would drop retracts and leave this node advertising content it no longer serves.
#[must_use]
pub fn split_batches(deltas: Vec<HoldingsDelta>) -> Vec<Vec<HoldingsDelta>> {
    if deltas.is_empty() {
        return Vec::new();
    }
    deltas
        .chunks(HOLDINGS_MAX_CHANGES)
        .map(<[HoldingsDelta]>::to_vec)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Ingress — the verified, rate-limited path into the local provider set
// ---------------------------------------------------------------------------------------------

/// The two local provider-set mutations an accepted announce performs.
///
/// A seam over [`dig_dht::DhtService`] so the ingress *policy* — verification, attribution,
/// rate limiting, replay rejection — is tested against an observable sink, with the live service
/// exercised separately by the real-wire integration test.
#[async_trait::async_trait]
pub trait HoldingsSink: Send + Sync {
    /// Admit a third-party provider record whose attribution the caller has already verified.
    ///
    /// Returns whether the record was actually ADMITTED. The distinction matters: dig-dht may
    /// legitimately refuse an ingest (over per-key or global capacity, or an already-expired
    /// `expires_at`), and an ingress that counted attempts instead of admissions would report a
    /// holder as discoverable when it is not — the kind of silent divergence that makes a "green"
    /// flywheel test meaningless.
    async fn ingest(&self, record: ProviderRecord) -> bool;
    /// Remove exactly `(content_key, provider_peer_id)`. Returns whether a record was removed.
    async fn remove(&self, content_key: &str, provider_peer_id: &str) -> bool;
}

/// A live [`dig_dht::DhtService`] as a [`HoldingsSink`].
#[async_trait::async_trait]
impl HoldingsSink for Arc<dig_dht::DhtService> {
    async fn ingest(&self, record: ProviderRecord) -> bool {
        matches!(
            self.ingest_verified_provider(record).await,
            dig_dht::provider_store::PutOutcome::Accepted
        )
    }

    async fn remove(&self, content_key: &str, provider_peer_id: &str) -> bool {
        self.remove_provider_record(content_key, provider_peer_id)
            .await
    }
}

/// Why an inbound announcement was not applied. Every variant means **nothing** was ingested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// The announcement failed `verify_holdings_announce` (bad batch size, peer-id/SPKI mismatch,
    /// unparseable key, or a signature that does not verify).
    Unverified(HoldingsError),
    /// The announcement is attributed to this node itself — only this node decides what it holds.
    SelfAttributed,
    /// `seq` did not advance beyond the highest already applied for this provider (replay or
    /// out-of-order delivery).
    StaleSeq {
        /// The rejected announcement's seq.
        seq: u64,
        /// The highest seq already applied for that provider.
        highest: u64,
    },
    /// The transport sender exhausted its announce or delta budget for the current window.
    RateLimited,
    /// `announced_at` is further from now than [`IngressLimits::max_announce_age_secs`], in either
    /// direction — the announcement is too old to act on, or dated too far ahead to be honest.
    Stale {
        /// The rejected announcement's signed `announced_at`.
        announced_at: u64,
        /// The receiver's clock when it was evaluated.
        now: u64,
    },
}

/// How many deltas of each kind an accepted announcement applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Applied {
    /// `Add` deltas ADMITTED as provider records (an ingest the DHT refused is not counted).
    pub ingested: usize,
    /// `Remove` deltas that removed an existing provider record.
    pub removed: usize,
}

/// Per-provider state: the highest applied `seq` plus that provider's announce bucket.
///
/// `highest_seq` is an `Option` rather than a sentinel: a provider that has never been seen has NO
/// watermark, which is different from one whose watermark is zero. Seeding a first sighting at
/// `seq - 1` would reject a conforming implementation that starts numbering at `0`, and SPEC does not
/// require `seq >= 1`.
#[derive(Debug, Clone, Copy)]
struct ProviderState {
    highest_seq: Option<u64>,
    window_start: u64,
    announces: u32,
    last_seen: u64,
}

/// Per-sender state: the neighbour's delta bucket.
#[derive(Debug, Clone, Copy)]
struct SenderState {
    window_start: u64,
    deltas: u32,
    last_seen: u64,
}

/// Every bound the ingress enforces: the two token buckets, the freshness window, and the capacity
/// of the two maps that hold the buckets themselves.
///
/// The map capacities live here — beside the budgets rather than as bare constants read at the point
/// of use — for one reason: a bound reachable only by an unaffordable fixture is a bound that never
/// gets tested. Crossing `tracked_providers` at its production value costs 8,193 P-256 identities, so
/// a suite that could not lower it asserted the map's growth against the SENDER map instead and left
/// the provider-side eviction unverified. Every field is therefore tunable by a test, and every
/// default is the production constant.
#[derive(Debug, Clone, Copy)]
pub struct IngressLimits {
    /// Applied announcements per **provider** per window.
    pub announces_per_provider: u32,
    /// Applied deltas per **transport sender** per window.
    pub deltas_per_sender: u32,
    /// Window length in seconds.
    pub window_secs: u64,
    /// Maximum absolute distance between `announced_at` and the receiver's clock.
    pub max_announce_age_secs: u64,
    /// Transport senders tracked before the least-recently-seen is evicted.
    pub tracked_senders: usize,
    /// Providers tracked before the least-recently-seen is evicted.
    pub tracked_providers: usize,
}

impl Default for IngressLimits {
    fn default() -> Self {
        Self {
            announces_per_provider: MAX_ANNOUNCES_PER_PROVIDER,
            deltas_per_sender: MAX_DELTAS_PER_SENDER,
            window_secs: RATE_WINDOW_SECS,
            max_announce_age_secs: MAX_ANNOUNCE_AGE_SECS,
            tracked_senders: MAX_TRACKED_SENDERS,
            tracked_providers: MAX_TRACKED_PROVIDERS,
        }
    }
}

/// The receive path for opcode-222 announcements: verify, attribute, bound, then apply.
///
/// One instance per node, shared across the inbound gossip task. Construct with [`Self::new`].
pub struct HoldingsIngress {
    /// This node's own 64-hex `peer_id`, so a self-attributed announce is dropped.
    self_peer_id: String,
    limits: IngressLimits,
    state: tokio::sync::Mutex<IngressState>,
}

#[derive(Default)]
struct IngressState {
    /// Delta buckets keyed by 64-hex transport sender.
    senders: HashMap<String, SenderState>,
    /// Replay watermark + announce bucket keyed by 64-hex provider.
    providers: HashMap<String, ProviderState>,
}

impl HoldingsIngress {
    /// Build an ingress for a node whose own `peer_id` is `self_peer_id` (64-hex).
    #[must_use]
    pub fn new(self_peer_id: String) -> Self {
        Self::with_limits(self_peer_id, IngressLimits::default())
    }

    /// Whether the real-time ingress is enabled for this process.
    ///
    /// `DIG_HOLDINGS_INGEST=0` (or `false`/`off`) disables it, leaving the node ANNOUNCING and
    /// discoverable through the durable DHT provider records. An operator facing an announcement flood
    /// needs a switch that does not require a downgrade; without one the only remedy is to stop the
    /// node.
    #[must_use]
    pub fn ingest_enabled_from_env() -> bool {
        ingest_enabled(std::env::var("DIG_HOLDINGS_INGEST").ok().as_deref())
    }

    /// [`Self::new`] with explicit bounds — used by tests to reach the budgets, the freshness window
    /// and the map capacities deterministically, without minting thousands of identities.
    #[must_use]
    pub fn with_limits(self_peer_id: String, limits: IngressLimits) -> Self {
        Self {
            // Canonicalized so gate 3 compares like with like. A caller that passes an
            // upper-case-spelled id would otherwise never match an inbound announcement, silently
            // disabling the self-attribution gate.
            self_peer_id: PeerId::from_hex(&self_peer_id).map_or(self_peer_id, |p| p.to_hex()),
            limits,
            state: tokio::sync::Mutex::new(IngressState::default()),
        }
    }

    /// How many senders and providers are currently tracked — the two capacity-bounded maps.
    ///
    /// Exists so the memory bound that keeps this ingress from becoming its own denial of service is
    /// a TESTED guarantee rather than a documented intention.
    pub async fn tracked_counts(&self) -> (usize, usize) {
        let state = self.state.lock().await;
        (state.senders.len(), state.providers.len())
    }

    /// Verify, bound and apply one inbound announcement. `now` is Unix seconds.
    ///
    /// `sender_peer_id` is the 64-hex `peer_id` of the **gossip peer the frame arrived from**, used
    /// only to charge the rate budget. It deliberately does NOT have to equal the announcement's
    /// provider: opcode 222 is a flood, so honest peers relay each other's announcements, and the
    /// signature — not the transport — is the attribution.
    ///
    /// # Attribution invariant
    ///
    /// This method takes no provider identity from its caller. The only provider id it can pass to
    /// [`HoldingsSink::remove`] or place in a [`ProviderRecord`] is
    /// [`HoldingsAnnounce::provider_peer_id`], which `verify_holdings_announce` has proven equals
    /// `SHA-256(provider_spki)` *and* signed this batch. A peer therefore cannot add or remove any
    /// record but its own, whatever it puts in the deltas — the wire carries no per-delta peer
    /// field to abuse.
    ///
    /// # Errors
    ///
    /// A [`Rejected`] describing the first failing gate; nothing is applied.
    pub async fn accept(
        &self,
        sink: &dyn HoldingsSink,
        sender_peer_id: &str,
        announce: &HoldingsAnnounce,
        now: u64,
    ) -> Result<Applied, Rejected> {
        // Gate 1 — authenticity. Fail-closed.
        verify_holdings_announce(announce).map_err(Rejected::Unverified)?;

        // Gate 2 — CANONICALIZE the identity, once, before it is compared to or keyed on anything.
        //
        // This is not defensive tidying, it is a correctness gate. Hex decoding is case-INSENSITIVE
        // and the signature covers the 32 DECODED bytes, so one identity has many valid spellings and
        // every one of them verifies. Treating the field as an opaque `String` therefore gives an
        // attacker a free bypass of any check built on it: a `String ==` against a lowercase self id
        // misses `0xAB…`, and a map keyed by spelling makes each variant a fresh provider with no
        // replay watermark. `PeerId::from_hex(..).to_hex()` collapses all of them to one value, and
        // NOTHING below this line may read `announce.provider_peer_id` again.
        let provider = PeerId::from_hex(&announce.provider_peer_id)
            .ok_or(Rejected::Unverified(HoldingsError::BadPeerIdHex))?;
        let provider_hex = provider.to_hex();

        // Gate 3 — never let the network tell us what we hold.
        if provider_hex == self.self_peer_id {
            return Err(Rejected::SelfAttributed);
        }

        // Gate 4 — bounded freshness. Evaluated before any state is touched, because a stale frame
        // must cost the receiver nothing at all. See [`MAX_ANNOUNCE_AGE_SECS`] for why a `Remove`
        // cannot be left to the `seq` watermark alone.
        if now.abs_diff(announce.announced_at) > self.limits.max_announce_age_secs {
            return Err(Rejected::Stale {
                announced_at: announce.announced_at,
                now,
            });
        }

        // Gates 5, 6 and 7 — replay rejection and the two rate buckets, decided together under one
        // lock so a concurrent flood cannot interleave two accepts past the same budget. The whole
        // decision is committed before any `await` on the sink, so a replay of this same seq is
        // already rejected while this batch is still being applied.
        let delta_cost = u32::try_from(announce.changes.len()).unwrap_or(u32::MAX);
        {
            let mut state = self.state.lock().await;
            state.admit(
                sender_peer_id,
                &provider_hex,
                announce.seq,
                delta_cost,
                now,
                &self.limits,
            )?;
        }

        Ok(self.apply(sink, &provider, &provider_hex, announce).await)
    }

    /// Apply a verified, budgeted batch. No egress — purely local provider-set mutation.
    ///
    /// Takes the CANONICAL provider identity as both its typed and hex forms, so neither the ingest
    /// nor the remove path can reach for the raw wire spelling.
    async fn apply(
        &self,
        sink: &dyn HoldingsSink,
        provider: &PeerId,
        provider_hex: &str,
        announce: &HoldingsAnnounce,
    ) -> Applied {
        let mut applied = Applied::default();
        for change in &announce.changes {
            match change {
                HoldingsDelta::Add {
                    content_key,
                    addresses,
                    expires_at,
                } => {
                    if sink
                        .ingest(ProviderRecord::new(
                            &Key::from_bytes(*content_key),
                            provider,
                            bounded_dht_addresses(addresses),
                            *expires_at,
                        ))
                        .await
                    {
                        applied.ingested += 1;
                    }
                }
                HoldingsDelta::Remove { content_key } => {
                    // The provider id is the CANONICALIZED verified signer, never a caller- or
                    // wire-supplied value: this is what makes a retract unable to de-list an honest
                    // holder, and the canonical form is what makes it resolve to the signer's own
                    // record rather than to a spelling that matches nothing.
                    if sink
                        .remove(&Key::from_bytes(*content_key).to_hex(), provider_hex)
                        .await
                    {
                        applied.removed += 1;
                    }
                }
            }
        }
        applied
    }
}

impl IngressState {
    /// The single chokepoint: decide replay and both rate buckets, and commit the charge.
    ///
    /// Every announcement that is applied passes through here exactly once. Nothing is charged
    /// unless the announcement is admitted, so a rejected flood cannot exhaust an honest peer's
    /// budget by proxy.
    ///
    /// # Errors
    ///
    /// [`Rejected::StaleSeq`] for a replayed or out-of-order announcement, or
    /// [`Rejected::RateLimited`] when either bucket is exhausted.
    fn admit(
        &mut self,
        sender: &str,
        provider: &str,
        seq: u64,
        deltas: u32,
        now: u64,
        limits: &IngressLimits,
    ) -> Result<(), Rejected> {
        // DECIDE FIRST, ALLOCATE ONLY ON SUCCESS.
        //
        // Nothing below reads through a `HashMap::entry`, because inserting before the gates is what
        // makes a REJECTED announcement grow the tracked set: the reject paths return early, so they
        // would skip the eviction at the end and the map would follow an attacker-minted key space
        // for the price of one ~180-byte frame per entry. Reading the current state into locals keeps
        // every rejection allocation-free.
        let current_provider = self.providers.get(provider).copied();
        let (provider_window, provider_announces, watermark) = match current_provider {
            // A window that has fully elapsed resets the bucket but NEVER the watermark: replay
            // protection is not a rate limit and must not lapse with one.
            Some(p) if now.saturating_sub(p.window_start) >= limits.window_secs => {
                (now, 0, p.highest_seq)
            }
            Some(p) => (p.window_start, p.announces, p.highest_seq),
            None => (now, 0, None),
        };
        if let Some(highest) = watermark {
            if seq <= highest {
                return Err(Rejected::StaleSeq { seq, highest });
            }
        }
        if provider_announces >= limits.announces_per_provider {
            return Err(Rejected::RateLimited);
        }

        let current_sender = self.senders.get(sender).copied();
        let (sender_window, sender_deltas) = match current_sender {
            Some(s) if now.saturating_sub(s.window_start) >= limits.window_secs => (now, 0),
            Some(s) => (s.window_start, s.deltas),
            None => (now, 0),
        };
        let charged = sender_deltas.saturating_add(deltas);
        if charged > limits.deltas_per_sender {
            return Err(Rejected::RateLimited);
        }

        // Every gate passed — NOW commit both sides.
        self.senders.insert(
            sender.to_string(),
            SenderState {
                window_start: sender_window,
                deltas: charged,
                last_seen: now,
            },
        );
        self.providers.insert(
            provider.to_string(),
            ProviderState {
                highest_seq: Some(seq),
                window_start: provider_window,
                announces: provider_announces.saturating_add(1),
                last_seen: now,
            },
        );

        // Evict AFTER committing so an entry just charged is never the victim of its own admission.
        evict_lru(&mut self.senders, limits.tracked_senders, |s| s.last_seen);
        evict_lru(&mut self.providers, limits.tracked_providers, |p| {
            p.last_seen
        });
        Ok(())
    }
}

/// Drop least-recently-stamped entries until `map` holds at most `cap`, oldest first.
///
/// Comparison allocates NOTHING: an earlier version built a `(stamp, String)` sort key, cloning a key
/// for every entry examined, on every removal, while holding the ingress lock — quadratic allocation
/// that turned a large tracked set into a wedged ingest task and a pinned worker thread. The tie-break
/// on key text is kept (it makes eviction deterministic for tests) but borrows instead of cloning, and
/// only the single chosen victim is cloned, which the borrow checker does require.
fn evict_lru<V>(map: &mut HashMap<String, V>, cap: usize, stamp: impl Fn(&V) -> u64) {
    while map.len() > cap {
        let Some(oldest) = map
            .iter()
            .min_by(|(a_key, a), (b_key, b)| stamp(a).cmp(&stamp(b)).then_with(|| a_key.cmp(b_key)))
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        map.remove(&oldest);
    }
}

/// A gossip-wire address as a dig-dht direct candidate.
///
/// The wire carries `host`/`port` only; dig-dht additionally ranks candidates by kind, and an
/// announced address is by definition one the holder claims to serve on directly.
fn to_dht_addr(addr: &GossipAddr) -> DhtAddr {
    DhtAddr::direct(addr.host.clone(), addr.port)
}

/// Map a wire address list to DHT addresses, mapping AT MOST
/// [`MAX_ADDRESSES_PER_RECORD`](dig_dht::MAX_ADDRESSES_PER_RECORD) of them.
///
/// The cap is applied HERE, before the map, and that placement is the whole point.
/// `ProviderRecord::new` also truncates, so the record this node ends up storing is correctly bounded
/// either way — but a wire announcement's address count is an attacker-declared `u16`, so mapping the
/// full list first would let a ~180-byte frame make this node allocate tens of thousands of owned
/// `String`s before dig-dht discarded all but eight. The observable property is therefore how many
/// addresses this function MAPS, not how many survive downstream; a test that can only see the stored
/// record cannot tell the two placements apart.
///
/// Taking the leading prefix (rather than ranking first) loses nothing: every wire address becomes a
/// [`DhtAddr::direct`], so all candidates share one rank and dig-dht's own rank-then-truncate would
/// keep the same prefix.
fn bounded_dht_addresses(addresses: &[GossipAddr]) -> Vec<DhtAddr> {
    addresses
        .iter()
        .take(dig_dht::MAX_ADDRESSES_PER_RECORD)
        .map(to_dht_addr)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Composition — flooding our own changes, and ingesting everyone else's
// ---------------------------------------------------------------------------------------------

/// How an announcement reaches the network. A seam over [`dig_gossip::GossipHandle`] so the
/// broadcaster's sequencing + batching are testable without a live pool.
#[async_trait::async_trait]
pub trait AnnounceTransport: Send + Sync {
    /// Flood one opcode-222 frame to every connected peer. Returns how many peers it reached.
    async fn flood(&self, announce: &HoldingsAnnounce) -> usize;
}

#[async_trait::async_trait]
impl AnnounceTransport for dig_gossip::GossipHandle {
    async fn flood(&self, announce: &HoldingsAnnounce) -> usize {
        self.broadcast(dig_gossip::frame_holdings_announce(announce), None)
            .await
            .unwrap_or(0)
    }
}

/// This node's outbound side: signs and floods an opcode-222 announcement per inventory change.
///
/// Owns the monotonic `seq` counter, because a receiver drops any announcement whose seq does not
/// advance — so exactly one place in the node may allocate them.
pub struct HoldingsBroadcaster {
    signer: EcdsaHoldingsSigner,
    /// Where this node serves the content it announces (signed, so no intermediary can repoint it).
    addresses: Vec<GossipAddr>,
    seq: std::sync::atomic::AtomicU64,
}

impl HoldingsBroadcaster {
    /// A broadcaster signing as `signer`, advertising `addresses` as where this node serves.
    ///
    /// `initial_seq` seeds the monotonic counter. It is deliberately a parameter rather than always
    /// zero: seq is per-provider replay protection at every receiver, and a node that restarts and
    /// resumes from 0 would have its announcements silently dropped by peers that still remember a
    /// higher seq. Passing a clock-derived value makes a restart resume ABOVE anything already
    /// announced. (Persisting the counter across restarts is #1477's durable-state work.)
    #[must_use]
    pub fn new(signer: EcdsaHoldingsSigner, addresses: Vec<GossipAddr>, initial_seq: u64) -> Self {
        Self {
            signer,
            addresses,
            seq: std::sync::atomic::AtomicU64::new(initial_seq),
        }
    }

    /// Flood the signed announcement(s) for one inventory reconcile. Returns how many frames were sent.
    ///
    /// A reconcile larger than one signed frame is split with [`split_batches`] rather than truncated,
    /// so a bulk cache-clear cannot silently drop retracts and leave this node advertising content it
    /// no longer serves. Each batch gets its own advancing seq.
    pub async fn announce_change(
        &self,
        transport: &dyn AnnounceTransport,
        gained: &[ContentId],
        lost: &[ContentId],
        now: u64,
    ) -> usize {
        let mut sent = 0;
        for batch in split_batches(deltas_for(now, gained, lost, &self.addresses)) {
            let seq = self
                .seq
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1);
            match HoldingsAnnounce::new_signed(&self.signer, seq, now, batch) {
                Ok(announce) => {
                    let peers = transport.flood(&announce).await;
                    tracing::debug!(
                        seq,
                        peers,
                        changes = announce.changes.len(),
                        "dig-node holdings: flooded an opcode-222 announcement"
                    );
                    sent += 1;
                }
                Err(e) => {
                    // Only reachable if `split_batches` ever produced an over-cap batch; logged
                    // rather than panicking so an inventory change can never abort the node.
                    tracing::warn!(error = %e, "dig-node holdings: refused to sign a batch");
                }
            }
        }
        sent
    }
}

/// Reconcile the node's DHT provider records against `cached` AND flood the matching real-time
/// announcement — the composition that actually turns caching a capsule into being discovered.
///
/// This is the node's ONE inventory-change reaction. Both halves take the SAME
/// [`InventoryDelta`](crate::dht::InventoryDelta), so the flood can never disagree with the provider
/// records it announces: a capsule cannot be announced as gained while its record says otherwise, and
/// a retract cannot be skipped. `holdings` is `None` on a node that cannot sign (it stays discoverable
/// through the durable records alone).
///
/// It lives here, taking the pieces it needs rather than a `Node`, so the composition is testable
/// against a real `DhtService` — the two halves passing in isolation says nothing about the wiring
/// between them, which is the whole point of the feature.
pub async fn reconcile_and_announce(
    dht: &crate::dht::DhtHandle,
    cached: &[crate::CachedCapsule],
    holdings: Option<(&HoldingsBroadcaster, &dyn AnnounceTransport)>,
    now: u64,
) -> crate::dht::InventoryDelta {
    let delta = dht.reconcile_inventory(cached).await;
    if let (Some((broadcaster, transport)), false) = (holdings, delta.is_empty()) {
        broadcaster
            .announce_change(transport, &delta.gained, &delta.lost, now)
            .await;
    }
    delta
}

/// Announce this node's ENTIRE current holdings as `Add` deltas, ignoring any diff. Returns how many
/// frames were sent.
///
/// Distinct from [`reconcile_and_announce`] on purpose, and the distinction is the #1734 fix. That
/// function announces a DELTA computed against the node's OWN local DHT records, which answers "what
/// changed here", not "what do my peers know". Those two diverge silently the moment an inventory
/// change happens with nobody listening: the local records move, the flood reaches zero peers, and
/// every later reconcile of the same inventory is a no-op — so a node that pinned before its first peer
/// (or restarted with content already cached, where the remembered set is seeded from disk) holds the
/// capsule, believes it announced, and is invisible to every peer it later connects to.
///
/// This function has no such state to be wrong about: it re-states the whole truth. Re-stating is safe
/// and cheap because an `Add` is idempotent at every receiver — a re-ingested record refreshes the same
/// provider entry under an advancing `seq` — so the repair costs one frame per inventory batch and can
/// never contradict the durable records it mirrors.
pub async fn announce_all_holdings(
    broadcaster: &HoldingsBroadcaster,
    transport: &dyn AnnounceTransport,
    cached: &[crate::CachedCapsule],
    now: u64,
) -> usize {
    let held = crate::dht::inventory_content_ids(cached);
    if held.is_empty() {
        return 0; // nothing to state; a node holding nothing has nothing to be invisible about
    }
    broadcaster
        .announce_change(transport, &held, &[], now)
        .await
}

/// The node's current cached inventory, as the holdings layer needs to read it.
///
/// A trait rather than a `&Node` so the peer-presence announcer below is drivable over a real gossip
/// wire without a node or a disk — the wiring across two nodes is the only place the #1734 defect is
/// visible, so that path has to be testable.
#[async_trait::async_trait]
pub trait HoldingsInventory: Send + Sync {
    /// The capsules this node currently holds.
    async fn current(&self) -> Vec<crate::CachedCapsule>;
}

/// Whether this node currently observes any connected peer — the edge the announce hangs on.
///
/// Kept as a tiny explicit state machine, separate from the task that drives it, because the EDGE
/// definition is the whole policy: it must fire on `0 -> N` (the node was unheard, so its holdings must
/// be re-stated) and must NOT fire when an already-peered pool merely grows (that would re-flood the
/// full inventory on every pool addition). A total loss of peers re-arms it, since a node whose only
/// peer went away is invisible again the moment one returns.
#[derive(Debug, Default)]
pub struct PoolPresence {
    has_peers: bool,
}

impl PoolPresence {
    /// Fold in an observed connected-peer count; `true` means "announce now".
    pub fn observe(&mut self, connected: usize) -> bool {
        let rising = connected > 0 && !self.has_peers;
        self.has_peers = connected > 0;
        rising
    }
}

/// Re-state this node's holdings to its peers whenever the pool rises from zero peers to some (#1734).
///
/// Spawned once at bring-up, and the reason "I hold X" and "peers know I hold X" cannot drift apart for
/// long: the very first non-empty pool observation announces the current inventory in full, so a pin
/// that happened with nobody connected — and a restart whose remembered inventory came off disk — both
/// repair themselves the moment a peer arrives, with no unpin/repin dance. Ends when the pool's event
/// channel closes.
///
/// Best-effort by construction: a failed subscribe logs and returns, leaving the durable DHT provider
/// records as the discovery path (a freshness degradation, never an outage).
///
/// A panic inside a single re-state is CONTAINED via [`catch_iteration`](crate::shared::catch_iteration)
/// so it cannot unwind out of the spawned task and silently stop this node from ever re-announcing its
/// holdings to newly-arriving peers for the rest of the process (#2068). The guarded iteration carries
/// only the borrowed `pool`/`inventory`/`broadcaster` handles (whose own locks are taken + released
/// INSIDE each awaited call, never held across the catch boundary — the broadcaster's `seq` is an
/// atomic, not a guard), so asserting its unwind-safety is sound; the next pool event simply re-reads
/// the connected count and re-arms.
pub async fn run_first_peer_announcer(
    pool: dig_gossip::GossipHandle,
    inventory: Arc<dyn HoldingsInventory>,
    broadcaster: Arc<HoldingsBroadcaster>,
) {
    // Subscribed BEFORE the first count is read, so a peer that connects between the two is still seen
    // as an event rather than silently falling into the gap.
    let mut events = match pool.subscribe_pool_events() {
        Ok(events) => events,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "holdings announce: no pool events; holdings pinned before the first peer will only \
                 be discoverable through the durable DHT records"
            );
            return;
        }
    };
    let mut presence = PoolPresence::default();
    let mut announce_if_rising = |connected: usize| presence.observe(connected);

    if announce_if_rising(pool.connected_pool_peers().len()) {
        restate_holdings(&pool, inventory.as_ref(), broadcaster.as_ref()).await;
    }
    loop {
        match events.recv().await {
            // The count is re-read from the pool rather than tracked from the event stream: the pool is
            // the authority on who is connected, and a lagged receiver would otherwise leave a
            // reconstructed count permanently wrong.
            Ok(_) => {
                if announce_if_rising(pool.connected_pool_peers().len()) {
                    // A panic mid-re-state is contained so the announcer survives to react to the next
                    // pool event (#2068); `None` just means this re-state panicked and was skipped.
                    let _ = crate::shared::catch_iteration(
                        "first_peer_announce",
                        restate_holdings(&pool, inventory.as_ref(), broadcaster.as_ref()),
                    )
                    .await;
                }
            }
            // Lagged: the count is re-read anyway, so a missed event costs nothing but a re-check.
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// Flood the node's whole current inventory to the pool, logging what it re-stated.
///
/// Takes the network as a `&dyn AnnounceTransport` rather than a concrete `GossipHandle` so a re-state
/// — the exact iteration [`run_first_peer_announcer`]'s loop guards against panic-death (#2068) — is
/// drivable against a mock transport with no live pool, which is how its per-iteration panic guard is
/// proven (see the tests below).
async fn restate_holdings(
    transport: &dyn AnnounceTransport,
    inventory: &dyn HoldingsInventory,
    broadcaster: &HoldingsBroadcaster,
) {
    let cached = inventory.current().await;
    let held = cached.len();
    let frames = announce_all_holdings(broadcaster, transport, &cached, now_unix_secs()).await;
    tracing::info!(
        held,
        frames,
        "dig-node holdings: peers arrived — re-announced this node's current holdings"
    );
}

/// Consume inbound opcode-222 frames from the gossip pool forever, applying each through `ingress`.
///
/// Spawned once at bring-up. Non-222 frames are ignored (other subscribers handle them), and a lagged
/// broadcast channel is tolerated: a missed announcement costs freshness, never correctness, because
/// the DHT's own republish/TTL cycle is the backstop. This loop performs NO egress — it is the reason
/// an inbound announcement cannot be amplified into outbound work.
///
/// A panic while applying a single frame is CONTAINED via
/// [`catch_iteration`](crate::shared::catch_iteration) so it cannot unwind out of the spawned task and
/// silently stop this node from ingesting ANY further peer holdings announcements for the rest of the
/// process (#2068). `recv().await` stays at the top of the loop, so a persistently-panicking source
/// cannot hot-spin — the loop still blocks on the next inbound frame between attempts. The guarded
/// iteration holds no lock across the catch boundary (the ingress's `state` is a tokio `Mutex` taken +
/// released INSIDE `accept`, never held by the loop), so asserting its unwind-safety is sound.
pub async fn run_holdings_ingest(
    mut inbound: tokio::sync::broadcast::Receiver<(dig_gossip::PeerId, dig_gossip::Message)>,
    ingress: Arc<HoldingsIngress>,
    sink: Arc<dig_dht::DhtService>,
) {
    loop {
        let (sender, msg) = match inbound.recv().await {
            Ok(pair) => pair,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::debug!(
                    skipped,
                    "dig-node holdings: inbound lagged; freshness only, DHT republish is the backstop"
                );
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        };
        let Some(announce) = dig_gossip::holdings_announce_payload(&msg) else {
            continue; // not an opcode-222 frame (or an undecodable one)
        };
        // A panic mid-apply is contained so the ingest loop survives to consume the next frame (#2068);
        // `None` just means this one frame's application panicked and was skipped.
        let _ = crate::shared::catch_iteration(
            "holdings_ingest",
            apply_inbound_announcement(
                &ingress,
                &sink,
                &hex::encode(sender.to_bytes()),
                &announce,
                now_unix_secs(),
            ),
        )
        .await;
    }
}

/// Verify, bound, apply and log ONE decoded inbound announcement — the awaited per-frame body of
/// [`run_holdings_ingest`], split out so the iteration its loop guards against panic-death (#2068) is a
/// standalone, testable unit. The loop wraps this in
/// [`catch_iteration`](crate::shared::catch_iteration); its panic-injection test drives this directly
/// against a [`HoldingsSink`] that panics mid-ingest — no live `DhtService` required.
///
/// Takes the sink as `&dyn HoldingsSink` (the same seam [`HoldingsIngress::accept`] consumes) precisely
/// so that injection is possible.
async fn apply_inbound_announcement(
    ingress: &HoldingsIngress,
    sink: &dyn HoldingsSink,
    sender_hex: &str,
    announce: &HoldingsAnnounce,
    now: u64,
) {
    // `provider_peer_id` is a `u16`-length-prefixed WIRE string: up to 65,535 bytes of arbitrary
    // UTF-8, newlines and terminal escapes included. Normalising it here means no peer-supplied
    // text can reach a log line, forge one, or drive a terminal escape. Logging at `debug` bounds
    // the VOLUME an attacker can cause; it does nothing about CONTENT, so content is handled by
    // never emitting the raw field at all.
    let canonical_provider =
        dig_dht::PeerId::from_hex(&announce.provider_peer_id).map(|p| p.to_hex());
    match ingress.accept(sink, sender_hex, announce, now).await {
        Ok(applied) => tracing::debug!(
            // Present whenever `accept` succeeded — it canonicalizes the same value.
            provider = canonical_provider.as_deref().unwrap_or("<unverified>"),
            ingested = applied.ingested,
            removed = applied.removed,
            "dig-node holdings: applied a verified announcement"
        ),
        Err(reason) => tracing::debug!(
            // `None` exactly when the id was not canonical hex, which is itself the diagnosis.
            provider = canonical_provider.as_deref().unwrap_or("<malformed>"),
            ?reason,
            "dig-node holdings: rejected an announcement"
        ),
    }
}

/// Wall-clock Unix seconds — the clock dig-dht clamps provider expiries against.
#[must_use]
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Whether an unset or given `DIG_HOLDINGS_INGEST` value leaves the ingress enabled.
///
/// Split out from [`HoldingsIngress::ingest_enabled_from_env`] so the decision is a pure function of
/// its input: reading the process environment inside a test would make the kill switch's own coverage
/// depend on test execution order.
///
/// FAIL-OPEN is deliberate and the safe direction here: an unrecognised value leaves the node
/// behaving exactly as it does today. The switch exists to let an operator SHED inbound work under a
/// flood, so a typo must never silently disable discovery instead.
fn ingest_enabled(raw: Option<&str>) -> bool {
    !matches!(
        raw.unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROPERTY: the address cap is applied BEFORE the map, so an attacker-declared count bounds the
    /// work this node does rather than only the record it keeps.
    ///
    /// Asserted on the mapper's own output because that is the only place the two placements differ:
    /// `ProviderRecord::new` truncates too, so any assertion made on the STORED record stays green
    /// with this cap deleted. Pinned from both sides — one over the bound must be cut, exactly at the
    /// bound must pass through whole — since a bound tested only from above cannot show it is the
    /// right bound.
    #[test]
    fn the_address_cap_is_applied_where_the_mapping_happens() {
        let cap = dig_dht::MAX_ADDRESSES_PER_RECORD;
        let declared = |n: usize| -> Vec<GossipAddr> {
            (0..n)
                .map(|i| GossipAddr {
                    host: format!("::{i:x}"),
                    port: 9_257,
                })
                .collect()
        };

        let over = bounded_dht_addresses(&declared(cap * 4));
        assert_eq!(
            over.len(),
            cap,
            "an oversized wire list must be cut to {cap} AT THE MAPPING, not merely stored bounded"
        );
        assert_eq!(
            over[0].host, "::0",
            "the kept addresses must be the declared prefix, in order"
        );

        assert_eq!(
            bounded_dht_addresses(&declared(cap)).len(),
            cap,
            "a list exactly at the bound must pass through whole"
        );
        assert!(
            bounded_dht_addresses(&[]).is_empty(),
            "an empty list maps to nothing"
        );
    }

    /// PROPERTY: the operator kill switch reads as OFF only for an explicit falsey value, and
    /// fail-opens on everything else including an unset variable.
    #[test]
    fn the_ingest_kill_switch_is_off_only_for_an_explicit_falsey_value() {
        for off in ["0", "false", "off", "no", "  OFF  ", "False"] {
            assert!(
                !ingest_enabled(Some(off)),
                "{off:?} must disable the ingress"
            );
        }
        for on in [
            None,
            Some(""),
            Some("1"),
            Some("true"),
            Some("yes"),
            Some("x"),
        ] {
            assert!(
                ingest_enabled(on),
                "{on:?} must leave the ingress enabled — the switch fails OPEN"
            );
        }
    }

    // -- The per-iteration panic guards on the two holdings background loops (#2068) ----------------

    /// A real §5.2 P-256 leaf identity + its `peer_id_hex`, so a test announcement is signed by a
    /// genuine identity that `verify_holdings_announce` accepts (mirrors the integration `TestPeer`).
    fn test_signer() -> (EcdsaHoldingsSigner, String) {
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
        (EcdsaHoldingsSigner::new(key_pair, spki), peer_id_hex)
    }

    /// A holdings inventory whose read PANICS — the cheapest seam that makes a real [`restate_holdings`]
    /// unwind, so the first-peer announcer's per-iteration guard can be proven to contain it.
    struct PanickingInventory;
    #[async_trait::async_trait]
    impl HoldingsInventory for PanickingInventory {
        async fn current(&self) -> Vec<crate::CachedCapsule> {
            panic!("injected holdings-inventory panic");
        }
    }

    /// A no-op announce transport: the panic test never reaches it (the inventory read panics first);
    /// it exists only to satisfy [`restate_holdings`]'s signature.
    struct NoopTransport;
    #[async_trait::async_trait]
    impl AnnounceTransport for NoopTransport {
        async fn flood(&self, _announce: &HoldingsAnnounce) -> usize {
            0
        }
    }

    /// **Proves:** a panic inside a single re-state is CONTAINED by [`run_first_peer_announcer`]'s
    /// [`catch_iteration`](crate::shared::catch_iteration) guard (#2068), so it never unwinds out of the
    /// spawned task and permanently stops this node re-announcing its holdings to arriving peers.
    ///
    /// NON-VACUOUS: remove the `catch_unwind` in `catch_iteration` (or `.await` `restate_holdings`
    /// directly here) and this test unwinds/aborts instead of returning `None` — proving the guard, not
    /// the harness, contains the panic.
    #[tokio::test]
    async fn a_panicking_re_state_is_caught_and_does_not_propagate() {
        let (signer, _peer_id) = test_signer();
        let broadcaster = HoldingsBroadcaster::new(signer, Vec::new(), 0);

        let contained = crate::shared::catch_iteration(
            "first_peer_announce",
            restate_holdings(&NoopTransport, &PanickingInventory, &broadcaster),
        )
        .await;

        assert_eq!(
            contained, None,
            "a panicking re-state must be contained as None, never propagated out of the loop"
        );
    }

    /// A holdings sink whose ingest PANICS — makes a real [`apply_inbound_announcement`] unwind at the
    /// exact point the ingest loop applies a verified announcement, so its per-frame guard is provable.
    struct PanickingSink;
    #[async_trait::async_trait]
    impl HoldingsSink for PanickingSink {
        async fn ingest(&self, _record: ProviderRecord) -> bool {
            panic!("injected holdings-sink ingest panic");
        }
        async fn remove(&self, _content_key: &str, _provider_peer_id: &str) -> bool {
            false
        }
    }

    /// **Proves:** a panic while applying a single inbound frame is CONTAINED by
    /// [`run_holdings_ingest`]'s [`catch_iteration`](crate::shared::catch_iteration) guard (#2068), so it
    /// never unwinds out of the spawned task and permanently stops this node ingesting any further peer
    /// holdings announcements. The announcement is genuinely signed and passes every `accept` gate, so
    /// the panic is raised by the REAL apply path reaching the sink — not by the harness.
    ///
    /// NON-VACUOUS: remove the `catch_unwind` in `catch_iteration` and this test unwinds/aborts instead
    /// of returning `None`.
    #[tokio::test]
    async fn a_panicking_frame_application_is_caught_and_does_not_propagate() {
        let (signer, provider_id) = test_signer();
        let now = now_unix_secs();
        // One valid `Add`, so `accept` passes verification, freshness, replay and both rate buckets and
        // reaches the sink's ingest (where the injected panic fires).
        let add = HoldingsDelta::Add {
            content_key: [7u8; 32],
            addresses: vec![GossipAddr {
                host: "::1".to_string(),
                port: 9_257,
            }],
            expires_at: now + ADVERTISED_TTL_SECS,
        };
        let announce = HoldingsAnnounce::new_signed(&signer, 1, now, vec![add])
            .expect("the fixture batch is within HOLDINGS_MAX_CHANGES");
        // A self id that is NOT the provider, so the self-attribution gate lets the frame through.
        let self_id = "00".repeat(32);
        assert_ne!(provider_id, self_id, "the provider must not be this node");
        let ingress = HoldingsIngress::with_limits(self_id, IngressLimits::default());
        let sender_hex = "ab".repeat(32);

        let contained = crate::shared::catch_iteration(
            "holdings_ingest",
            apply_inbound_announcement(&ingress, &PanickingSink, &sender_hex, &announce, now),
        )
        .await;

        assert_eq!(
            contained, None,
            "a panicking frame application must be contained as None, never propagated out of the loop"
        );
    }
}
