//! What this node learned FIRST-HAND about who holds what, and which asks it has already walked —
//! the two pieces of remembered state the recursive ask needs (dig-node#275, dig-node#273).
//!
//! # One structure, because both are the same shape
//!
//! Both are bounded, TTL'd maps a stranger can drive: a provider cache keyed by content, and a
//! seen-set keyed by request id. Writing them twice would be two places to get the eviction bound
//! wrong, so [`TtlMap`] holds the policy once and each use names only its own key, TTL and bound.
//!
//! # The cache remembers FIRST-HAND records ONLY, and that is a security property
//!
//! A first-hand record is one this node obtained itself — its own DHT walk. A hearsay record is one a
//! hop relayed. **Only first-hand records are stored**, which keeps two things true without having to
//! argue for either:
//!
//! * SPEC §10.4.4's *"forwarded records MUST NOT be stored, re-served as this node's own
//!   authoritative claim, or published"* holds **unamended** — hearsay never enters this module. A
//!   cache that stored hearsay would let one lying hop plant a fabricated holder that this node then
//!   re-serves as its own knowledge for the whole TTL, which is a far better attack than lying once.
//! * The privacy surface the epic flags — *"a record of who holds what is also a record of what this
//!   node looked for"* — is answered by CONSTRUCTION rather than by policy. A first-hand-only cache
//!   records only what this node's own lookup already established, which it necessarily already knew.
//!
//! It is **in memory only, never persisted**. It therefore does not add an at-rest interest history
//! and does not come under NC-2 sealing: the process ending forgets it, which is the correct lifetime
//! for a performance cache whose contents are an interest log.
//!
//! # Every entry is a candidate to DIAL, never a fact
//!
//! A cached provider is exactly as untrusted as a freshly-looked-up one (NC-12). The whole-resource
//! merkle bind against the chain-anchored root is what admits bytes, so a stale entry costs one
//! wasted dial and never a wrong read. That is the whole reason a cache is safe here at all.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dig_dht::{ContentId, ProviderRecord};

/// How long a first-hand holder record stays usable.
///
/// It is [`ADVERTISED_TTL_SECS`](super::holdings::ADVERTISED_TTL_SECS) deliberately, not a number
/// chosen here: that is already how long this ecosystem treats a holder's own signed holdings
/// announce as live, so a cached record expires exactly when the claim behind it would have. Choosing
/// independently would mean this node dials holders the network has already stopped believing in —
/// the same wasted-dial cost that eviction-without-retraction causes.
pub(crate) const HOLDER_CACHE_TTL: Duration =
    Duration::from_secs(super::holdings::ADVERTISED_TTL_SECS);

/// The most content keys the holder cache will remember at once.
///
/// A cache of peer claims that a stranger can grow is a memory target, and misses are
/// stranger-driven: anyone may ask about content this node does not have. The bound is what makes the
/// footprint a constant instead of a function of how many distinct things strangers ask about.
pub(crate) const HOLDER_CACHE_CAPACITY: usize = 4_096;

/// The most in-flight request ids the seen-set tracks at once. Same reasoning as
/// [`HOLDER_CACHE_CAPACITY`]: the population is driven by strangers, so it is bounded.
pub(crate) const ASK_SEEN_CAPACITY: usize = 8_192;

/// A bounded, TTL'd map with deterministic eviction.
///
/// # The eviction order, and why it is by AGE rather than by use
///
/// On a full insert, expired entries are purged first; if that frees nothing, the OLDEST entry by
/// insertion goes. Age is used rather than recency-of-use because every entry here is already
/// lifetime-bounded by its TTL — an entry's value decays with age whether or not it was read, so
/// re-reading a nearly-stale provider record is no reason to keep it ahead of a fresh one.
///
/// The important property is simply that the bound is ENFORCED and the victim is not
/// attacker-chosen: eviction cannot be steered into dropping one specific entry without also filling
/// the map, which the bound already prices.
struct TtlMap<K, V> {
    entries: Mutex<HashMap<K, (Instant, V)>>,
    ttl: Duration,
    capacity: usize,
}

impl<K: Eq + Hash + Clone, V: Clone> TtlMap<K, V> {
    fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            capacity,
        }
    }

    /// The value stored under `key`, unless it has aged past the TTL.
    ///
    /// An expired entry reads as absent AND is removed, so a key that is looked up but never
    /// re-inserted cannot occupy the bound forever.
    fn get(&self, key: &K, now: Instant) -> Option<V> {
        let mut entries = self.lock();
        let (stored_at, value) = entries.get(key)?;
        if now.duration_since(*stored_at) >= self.ttl {
            entries.remove(key);
            return None;
        }
        Some(value.clone())
    }

    /// Store `value` under `key`, evicting to stay inside the bound.
    fn insert(&self, key: K, value: V, now: Instant) {
        let mut entries = self.lock();
        entries.retain(|_, (stored_at, _)| now.duration_since(*stored_at) < self.ttl);
        while entries.len() >= self.capacity && !entries.contains_key(&key) {
            let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, (stored_at, _))| *stored_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.remove(&oldest);
        }
        entries.insert(key, (now, value));
    }

    /// Forget `key`, whatever its age.
    fn remove(&self, key: &K) {
        self.lock().remove(key);
    }

    /// A poisoned lock means another thread panicked while holding it; the map is a cache, so the
    /// correct recovery is to carry on with whatever it holds rather than propagate the panic into
    /// every later lookup.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<K, (Instant, V)>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Which peers this node established, ITSELF, are holding which content (dig-node#275).
///
/// Reading it lets a second request for the same content dial a known holder instead of repeating
/// discovery. See the module docs for why only first-hand records are admitted.
pub(crate) struct FirstHandHolderCache {
    holders: TtlMap<ContentId, Vec<ProviderRecord>>,
}

impl FirstHandHolderCache {
    pub(crate) fn new() -> Self {
        Self {
            holders: TtlMap::new(HOLDER_CACHE_TTL, HOLDER_CACHE_CAPACITY),
        }
    }

    /// The first-hand holders remembered for `content`, if any are still fresh.
    pub(crate) fn get(&self, content: &ContentId) -> Option<Vec<ProviderRecord>> {
        self.holders.get(content, Instant::now())
    }

    /// Remember `records` as this node's own first-hand knowledge of who holds `content`.
    ///
    /// **The caller is responsible for passing first-hand records only.** An empty slate is not
    /// stored: "I found nobody" is a fact about one moment, and caching it would suppress rediscovery
    /// for the whole TTL — turning one unlucky lookup into an hour of manufactured absence.
    pub(crate) fn remember(&self, content: &ContentId, records: &[ProviderRecord]) {
        if records.is_empty() {
            return;
        }
        self.holders
            .insert(*content, records.to_vec(), Instant::now());
    }

    /// Forget `content`, because none of the cached holders could actually be reached.
    ///
    /// This is the counterpart the DHT's own cache invalidation already has (dig-dht SPEC §6.8): a
    /// remembered set that is entirely unreachable must not be replayed for the rest of its TTL.
    pub(crate) fn forget(&self, content: &ContentId) {
        self.holders.remove(content);
    }
}

/// The request ids this node has already walked, so the same ask arriving twice by different paths is
/// forwarded once (dig-node#273).
///
/// # Why excluding the requestor was not enough
///
/// `dig_sex::discovery::decide_forward` excludes the immediate requestor and this node, which stops an
/// immediate echo. It cannot stop a DIAMOND: in any graph that is not a tree the same ask reaches one
/// node by two paths, and without an identity neither arrival recognises the other. The graph then
/// re-walks itself and the real fan-out cost far exceeds `fan_out ^ hop_cap`.
pub(crate) struct AskSeenSet {
    seen: TtlMap<AskId, ()>,
}

/// A request identity: opaque, 16 bytes, minted by the ORIGINATOR and echoed unchanged by every hop.
///
/// It is deliberately not derived from the content or the requestor. A content-derived id would make
/// two independent readers asking about the same capsule collide, so the second would be silently
/// refused; a requestor-derived id would publish who is asking to every hop, widening exactly the
/// disclosure SPEC §10.4.5 bounds.
pub(crate) type AskId = [u8; 16];

impl AskSeenSet {
    pub(crate) fn new() -> Self {
        Self {
            // A request cannot outlive the largest budget any hop is allowed to grant it, so an entry
            // older than that ceiling cannot still be in flight and holding it proves nothing. The TTL
            // is read off the protocol's own bound rather than chosen.
            seen: TtlMap::new(
                super::forwarded_ask::MAX_FORWARDED_ASK_BUDGET,
                ASK_SEEN_CAPACITY,
            ),
        }
    }

    /// Claim `id` for this node. `true` means it is new and may be forwarded; `false` means this ask
    /// has already been walked here and must not be walked again.
    pub(crate) fn claim(&self, id: AskId) -> bool {
        let now = Instant::now();
        if self.seen.get(&id, now).is_some() {
            return false;
        }
        self.seen.insert(id, (), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_dht::{CandidateAddr, PeerId};

    fn content(byte: u8) -> ContentId {
        ContentId::store([byte; 32])
    }

    fn provider(byte: u8, content: &ContentId) -> ProviderRecord {
        ProviderRecord::new(
            &content.to_key(),
            &PeerId::from_bytes([byte; 32]),
            vec![CandidateAddr::direct(format!("10.0.0.{byte}"), 9444)],
            u64::MAX,
        )
    }

    /// **Proves:** a remembered first-hand slate is returned to a later lookup for the same content —
    /// the whole point of requirement 7.
    #[test]
    fn a_remembered_first_hand_slate_is_returned_to_the_next_lookup() {
        let cache = FirstHandHolderCache::new();
        cache.remember(&content(1), &[provider(7, &content(1))]);

        let hit = cache.get(&content(1)).expect("the slate is remembered");

        assert_eq!(hit.len(), 1);
        assert_eq!(
            hit[0].provider_peer_id,
            PeerId::from_bytes([7; 32]).to_hex(),
            "the same holder comes back, not merely some holder"
        );
    }

    /// **Proves:** the cache is keyed by CONTENT, so remembering one capsule does not answer for
    /// another.
    ///
    /// **Fixture design:** two distinct keys with only ONE populated. A cache that ignored its key and
    /// returned any stored slate would satisfy the test above identically — this is the second actor
    /// that makes that impossible.
    #[test]
    fn a_slate_remembered_for_one_content_does_not_answer_for_another() {
        let cache = FirstHandHolderCache::new();
        cache.remember(&content(1), &[provider(7, &content(1))]);

        assert!(
            cache.get(&content(2)).is_none(),
            "content 2 was never looked up, so nothing may be asserted about it"
        );
    }

    /// **Proves:** an EMPTY slate is not stored, so a lookup that found nobody does not suppress
    /// rediscovery for the TTL.
    ///
    /// **Catches:** the natural implementation — cache whatever the lookup returned — which converts
    /// one unlucky lookup into an hour of manufactured absence for that content. That is the same
    /// "one empty answer becomes an authoritative absence" failure dig-node#273 fixes on the wire,
    /// and it would have been reintroduced here by the cache.
    #[test]
    fn an_empty_slate_is_never_remembered() {
        let cache = FirstHandHolderCache::new();
        cache.remember(&content(1), &[]);

        assert!(cache.get(&content(1)).is_none());
    }

    /// **Proves:** an unreachable slate can be forgotten before its TTL, so the next attempt runs a
    /// real lookup.
    #[test]
    fn an_unreachable_slate_can_be_forgotten_before_its_ttl() {
        let cache = FirstHandHolderCache::new();
        cache.remember(&content(1), &[provider(9, &content(1))]);

        cache.forget(&content(1));

        assert!(cache.get(&content(1)).is_none());
    }

    /// **Proves:** an entry past its TTL reads as absent.
    ///
    /// **Fixture design — the TTL is pinned from BOTH sides against an explicit `NOW`.** The map is
    /// driven through its `Instant`-taking internals rather than the wall clock, because a test that
    /// passed a small TTL through a wall-clock API would find every entry already expired and would
    /// assert expiry while never exercising the fresh path. At exactly the TTL the entry is gone
    /// (the boundary is exclusive) and one tick under it is still present.
    #[test]
    fn an_entry_expires_at_its_ttl_and_not_before() {
        let map: TtlMap<u8, &str> = TtlMap::new(Duration::from_secs(60), 8);
        let now = Instant::now();
        map.insert(1, "value", now);

        assert_eq!(
            map.get(&1, now + Duration::from_secs(59)),
            Some("value"),
            "one second under the TTL is still live"
        );
        assert_eq!(
            map.get(&1, now + Duration::from_secs(60)),
            None,
            "at the TTL it is gone"
        );
    }

    /// **Proves:** the capacity bound is ENFORCED, and the survivor is the newest rather than
    /// whatever the hash map happened to hold.
    ///
    /// **Fixture design:** entries are inserted with STRICTLY INCREASING timestamps inside one TTL,
    /// so nothing expires and the bound is the only thing that can remove anything. A fixture that
    /// let the TTL do the work would pass against a map with no bound at all — which is exactly the
    /// memory target this constant exists to prevent.
    #[test]
    fn the_capacity_bound_evicts_the_oldest_and_keeps_the_newest() {
        let map: TtlMap<u8, u8> = TtlMap::new(Duration::from_secs(600), 3);
        let start = Instant::now();
        for i in 0..3u8 {
            map.insert(i, i, start + Duration::from_secs(u64::from(i)));
        }

        map.insert(9, 9, start + Duration::from_secs(9));

        assert_eq!(map.lock().len(), 3, "the bound holds");
        assert_eq!(
            map.get(&0, start + Duration::from_secs(9)),
            None,
            "the oldest went"
        );
        assert_eq!(
            map.get(&9, start + Duration::from_secs(9)),
            Some(9),
            "and the newest is what it went for"
        );
    }

    /// **Proves:** the same ask id is claimable exactly once, which is what makes a diamond re-walk
    /// finite.
    ///
    /// **Fixture design:** a SECOND, different id is claimed after the duplicate is refused. Without
    /// it, an implementation that refused everything after the first claim would pass — and that
    /// implementation answers no asks at all.
    #[test]
    fn an_ask_id_is_claimable_once_and_a_different_id_is_unaffected() {
        let seen = AskSeenSet::new();

        assert!(seen.claim([7u8; 16]), "first arrival walks");
        assert!(
            !seen.claim([7u8; 16]),
            "the diamond's second arrival does not"
        );
        assert!(
            seen.claim([8u8; 16]),
            "an unrelated ask is not collateral damage"
        );
    }
}
