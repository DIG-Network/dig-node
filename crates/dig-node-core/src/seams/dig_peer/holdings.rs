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
//! | **Forged attribution** — naming another peer as a holder, or as *not* a holder | An announce's provider identity is [`HoldingsAnnounce::provider_peer_id`], which `verify_holdings_announce` proves equals `SHA-256(provider_spki)` and which signed the batch. [`HoldingsIngress::accept`] takes **no** caller-supplied provider id, so no code path can name a peer the signature does not attribute (see [`HoldingsIngress::accept`]). |
//! | **Amplification** — one cheap inbound message causing outbound work | The ingress performs **zero egress**: it never re-broadcasts, dials, probes, or fetches. Its whole cost is bounded local map work. |
//! | **Flood / Sybil eviction** — evicting an honest holder from a full provider set | Two token buckets at ONE chokepoint ([`RateLimits`]): announcements per *provider* and deltas per *transport sender*. They are keyed differently on purpose — see [`MAX_DELTAS_PER_SENDER`] for why each covers the other's weakness. A rejected announcement charges neither, so the limiter cannot itself be turned into the denial of service. |
//! | **Replay** — resurrecting a retracted record, or undoing a newer announce | Per-provider monotonic [`HoldingsAnnounce::seq`]; an announce at or below the highest seq already applied for that provider is dropped. |
//! | **Self-poisoning** — replaying our own announce back at us | An announce attributed to this node's own `peer_id` is dropped; only this node decides what it holds. |
//! | **Unbounded state** — the guard maps themselves becoming the DoS | Both maps are capacity-bounded with LRU eviction ([`MAX_TRACKED_SENDERS`], [`MAX_TRACKED_PROVIDERS`]). |
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

/// Transport senders tracked before the least-recently-seen is evicted.
///
/// The key is a peer this node holds a live mTLS link to, so the live key space is the connected
/// pool; this cap is headroom over any realistic pool rather than the primary bound.
pub const MAX_TRACKED_SENDERS: usize = 1_024;

/// Providers tracked (latest `seq` + announce bucket) before the least-recently-seen is evicted.
///
/// Bounded because the provider id inside an announce is attacker-chosen. Eviction degrades
/// gracefully in both directions: losing a seq permits a replay of *that provider's own* signed
/// announce (bounded staleness, never cross-peer censorship — the retract path can still only touch
/// the signer's own record), and losing an announce bucket is backstopped by
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
#[derive(Debug, Clone, Copy)]
struct ProviderState {
    highest_seq: u64,
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

/// The two budgets enforced at the ingress chokepoint.
#[derive(Debug, Clone, Copy)]
pub struct RateLimits {
    /// Applied announcements per **provider** per window.
    pub announces_per_provider: u32,
    /// Applied deltas per **transport sender** per window.
    pub deltas_per_sender: u32,
    /// Window length in seconds.
    pub window_secs: u64,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            announces_per_provider: MAX_ANNOUNCES_PER_PROVIDER,
            deltas_per_sender: MAX_DELTAS_PER_SENDER,
            window_secs: RATE_WINDOW_SECS,
        }
    }
}

/// The receive path for opcode-222 announcements: verify, attribute, bound, then apply.
///
/// One instance per node, shared across the inbound gossip task. Construct with [`Self::new`].
pub struct HoldingsIngress {
    /// This node's own 64-hex `peer_id`, so a self-attributed announce is dropped.
    self_peer_id: String,
    limits: RateLimits,
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
        Self::with_limits(self_peer_id, RateLimits::default())
    }

    /// [`Self::new`] with explicit budgets — used by tests to reach the limits deterministically
    /// without emitting thousands of frames.
    #[must_use]
    pub fn with_limits(self_peer_id: String, limits: RateLimits) -> Self {
        Self {
            self_peer_id,
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
        // Gate 1 — authenticity. Fail-closed: everything after this point trusts
        // `announce.provider_peer_id` as the signer, and nothing else.
        verify_holdings_announce(announce).map_err(Rejected::Unverified)?;

        // Gate 2 — never let the network tell us what we hold.
        if announce.provider_peer_id == self.self_peer_id {
            return Err(Rejected::SelfAttributed);
        }

        // Gates 3, 4 and 5 — replay rejection and the two rate buckets, decided together under one
        // lock so a concurrent flood cannot interleave two accepts past the same budget. The whole
        // decision is committed before any `await` on the sink, so a replay of this same seq is
        // already rejected while this batch is still being applied.
        let delta_cost = u32::try_from(announce.changes.len()).unwrap_or(u32::MAX);
        {
            let mut state = self.state.lock().await;
            state.admit(
                sender_peer_id,
                &announce.provider_peer_id,
                announce.seq,
                delta_cost,
                now,
                &self.limits,
            )?;
        }

        Ok(self.apply(sink, announce).await)
    }

    /// Apply a verified, budgeted batch. No egress — purely local provider-set mutation.
    async fn apply(&self, sink: &dyn HoldingsSink, announce: &HoldingsAnnounce) -> Applied {
        let Some(provider) = PeerId::from_hex(&announce.provider_peer_id) else {
            // Unreachable: gate 1 proved the hex decodes. Treated as "apply nothing" rather than
            // panicking, so a future wire change can never turn a parse skew into a node crash.
            return Applied::default();
        };
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
                            &provider,
                            addresses.iter().map(to_dht_addr).collect(),
                            *expires_at,
                        ))
                        .await
                    {
                        applied.ingested += 1;
                    }
                }
                HoldingsDelta::Remove { content_key } => {
                    // The provider id is the VERIFIED signer, never a caller- or wire-supplied
                    // value: this is what makes a retract unable to de-list an honest holder.
                    if sink
                        .remove(
                            &Key::from_bytes(*content_key).to_hex(),
                            &announce.provider_peer_id,
                        )
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
        limits: &RateLimits,
    ) -> Result<(), Rejected> {
        let provider_state = self
            .providers
            .entry(provider.to_string())
            .or_insert_with(|| ProviderState {
                // `highest_seq` starts one below the incoming seq so a provider's FIRST announcement
                // is admitted at whatever seq it carries; only a non-advancing seq is a replay.
                highest_seq: seq.saturating_sub(1),
                window_start: now,
                announces: 0,
                last_seen: now,
            });
        if now.saturating_sub(provider_state.window_start) >= limits.window_secs {
            provider_state.window_start = now;
            provider_state.announces = 0;
        }
        if seq <= provider_state.highest_seq {
            return Err(Rejected::StaleSeq {
                seq,
                highest: provider_state.highest_seq,
            });
        }
        if provider_state.announces >= limits.announces_per_provider {
            return Err(Rejected::RateLimited);
        }

        let sender_state = self
            .senders
            .entry(sender.to_string())
            .or_insert_with(|| SenderState {
                window_start: now,
                deltas: 0,
                last_seen: now,
            });
        if now.saturating_sub(sender_state.window_start) >= limits.window_secs {
            sender_state.window_start = now;
            sender_state.deltas = 0;
        }
        let charged = sender_state.deltas.saturating_add(deltas);
        if charged > limits.deltas_per_sender {
            return Err(Rejected::RateLimited);
        }
        sender_state.deltas = charged;
        sender_state.last_seen = now;

        // Both buckets fit — commit the provider side too. Re-looked-up because the sender borrow
        // above ended; the entry is present since it was just inserted.
        if let Some(p) = self.providers.get_mut(provider) {
            p.announces = p.announces.saturating_add(1);
            p.highest_seq = seq;
            p.last_seen = now;
        }

        // Evict AFTER charging so an entry just charged is never the victim of its own admission.
        evict_lru(&mut self.senders, MAX_TRACKED_SENDERS, |s| s.last_seen);
        evict_lru(&mut self.providers, MAX_TRACKED_PROVIDERS, |p| p.last_seen);
        Ok(())
    }
}

/// Drop least-recently-stamped entries until `map` holds at most `cap`.
fn evict_lru<V>(map: &mut HashMap<String, V>, cap: usize, stamp: impl Fn(&V) -> u64) {
    while map.len() > cap {
        let Some(oldest) = map
            .iter()
            .min_by_key(|(k, v)| (stamp(v), (*k).clone()))
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

/// Consume inbound opcode-222 frames from the gossip pool forever, applying each through `ingress`.
///
/// Spawned once at bring-up. Non-222 frames are ignored (other subscribers handle them), and a lagged
/// broadcast channel is tolerated: a missed announcement costs freshness, never correctness, because
/// the DHT's own republish/TTL cycle is the backstop. This loop performs NO egress — it is the reason
/// an inbound announcement cannot be amplified into outbound work.
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
        let now = now_unix_secs();
        match ingress
            .accept(&sink, &hex::encode(sender.to_bytes()), &announce, now)
            .await
        {
            Ok(applied) => tracing::debug!(
                provider = %announce.provider_peer_id,
                ingested = applied.ingested,
                removed = applied.removed,
                "dig-node holdings: applied a verified announcement"
            ),
            // Rejections are the common case under adversarial load, so they stay at debug: an
            // attacker must never be able to inflate this node's log volume.
            Err(reason) => tracing::debug!(
                provider = %announce.provider_peer_id,
                ?reason,
                "dig-node holdings: rejected an announcement"
            ),
        }
    }
}

/// Wall-clock Unix seconds — the clock dig-dht clamps provider expiries against.
#[must_use]
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
