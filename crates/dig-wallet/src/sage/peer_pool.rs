//! A HELD pool of Chia full-node peers (dig_ecosystem#2606), replacing the
//! one-connection-plus-throwaway-probes shape, and closing the unconditional loopback dial bias
//! (dig_ecosystem#2573).
//!
//! # What changed, and why a pool
//!
//! Before this module the supervisor held exactly ONE peer connection, and every corroboration
//! round opened [`quorum::QUORUM_SAMPLE`] brand-new connections, asked them one question and
//! dropped them. Five peers were contacted per round and one survived it. That is expensive
//! (a full TLS handshake and a `new_peak_wallet` wait per member, per round), fragile (a round
//! fails whenever discovery is slow), and — the part that matters — it made the quorum's
//! independence depend on a dial helper that is not independent (below).
//!
//! A pool is the same peers, KEPT. Corroboration then draws its sample from members that are
//! already connected and already announcing their own peaks, so a round costs no dials at all.
//!
//! # This does NOT add a second subscriber
//!
//! [`crate::sage::sync_supervisor::SyncSession`] documents why exactly ONE peer subscribes:
//! `request_puzzle_state(subscribe = true)` is per-connection state, and N subscribed peers
//! would drive N interleaved `rollback_above` calls into a DB with a single writer. That
//! invariant is untouched. A pool member is a held READ-ONLY connection; precisely one member is
//! additionally promoted to the writer session. Redundancy is bought for the QUESTION path,
//! never for the write path.
//!
//! # The bias this closes (#2573)
//!
//! `chia_query::peer::connect::connect_random_peer` tries `127.0.0.1:8444` before any
//! introducer, unconditionally, and then returns the FIRST address in a concurrent batch that
//! answers. Under one held connection that was a hazard; under a pool it is a collapse. Filling
//! five slots with five calls to that helper on a host with a co-resident full node yields FIVE
//! connections to the same process, which then supplies an entire "independent" quorum by
//! itself. The previous round compensated with a retry-until-distinct loop, and named resolving
//! the list once as the stronger form; this is that form.
//!
//! So the pool never dials a helper that chooses for it. It resolves a candidate ADDRESS LIST
//! once ([`AddressBook`]) and dials from it, admitting each address at most once
//! ([`PeerPool::fill`]). Loopback has exactly one legitimate role left, and it is stated:
//! **loopback is a member only when the OPERATOR asked for it** — a `user_managed` row naming a
//! loopback address, or `TRUSTED_FULLNODE` — never because it happened to be listening.
//!
//! # §908
//!
//! Every connection here is a chain READ. No seed is reachable from this module and nothing in
//! it can sign.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

use super::quorum::{self, EntropySource, PeakClaim};

/// How many peers the pool tries to hold.
///
/// Five, matching Sage's `target_peers` default and the envelope
/// [`quorum`] already reasons inside: a [`quorum::QUORUM_SAMPLE`] of 4 must be drawable from
/// SURVIVORS, so the pool has to hold at least one more peer than a sample needs or the loss of
/// a single member makes every subsequent round [`quorum::Verdict::Insufficient`]. Five is that
/// floor plus Sage parity, rather than a number chosen for roundness.
pub const TARGET_PEERS: usize = 5;

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/// The candidate addresses the pool may dial, resolved ONCE per pool.
///
/// A seam, and specifically NOT a "give me a peer" helper: the difference between this trait and
/// `connect_random_peer` is the whole of #2573. A resolver that returns a LIST lets the pool
/// enforce distinctness and lets selection be uniform over the list; a helper that returns one
/// already-chosen peer moves both decisions somewhere the pool cannot see them.
#[async_trait::async_trait]
pub trait AddressBook: Send + Sync {
    /// Every address worth trying, best-first, already de-duplicated and shuffled.
    async fn addresses(&self) -> Vec<SocketAddr>;
}

/// One held peer connection, as the pool and its consumers use it.
///
/// Deliberately narrow: a pool member is asked what it CLAIMS and asked one settled-height
/// question. It is never handed the replica.
#[async_trait::async_trait]
pub trait PoolPeer: Send + Sync {
    /// This peer's own latest peak claim, or `None` if it has not announced one yet.
    ///
    /// PER PEER, which is the property corroboration rests on. A pool-wide "highest peak seen"
    /// (the shape `chia_query`'s pool uses) would let one member's claim become every member's
    /// claim, and the quorum would then be comparing one number with itself four times.
    fn peak(&self) -> Option<PeakClaim>;

    /// This peer's answer to "what is the canonical header hash at `height`?".
    ///
    /// `None` covers both a refusal and a peer that does not have the block; for voting purposes
    /// they are the same thing — an absent vote, which counts against reaching a quorum.
    async fn header_hash_at(&self, height: u32) -> Option<chia_protocol::Bytes32>;
}

/// Opens one connection to one CHOSEN address.
///
/// The pool decides who to dial; the dialer only carries it out.
#[async_trait::async_trait]
pub trait PeerDialer: Send + Sync {
    /// Connect to `addr`, or fail. A failure is ordinary — the pool moves to the next candidate.
    async fn dial(&self, addr: SocketAddr) -> Option<Arc<dyn PoolPeer>>;
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

/// A peer the pool is holding right now.
#[derive(Clone)]
pub struct Member {
    /// The address dialled. Doubles as the member's identity, so distinctness is address
    /// distinctness.
    pub addr: SocketAddr,
    /// The live connection.
    pub peer: Arc<dyn PoolPeer>,
}

impl Member {
    /// This member as a [`quorum::Candidate`], if it has announced a peak to be judged on.
    ///
    /// A member with no claim yet is not a candidate: [`quorum::common_height`] settles the
    /// question from claims, so admitting a claimless member would either need a fabricated
    /// height or would silently drag the settled height down.
    pub fn candidate(&self) -> Option<quorum::Candidate> {
        self.peer.peak().map(|claim| quorum::Candidate {
            id: self.addr.to_string(),
            claim,
        })
    }
}

// ---------------------------------------------------------------------------
// The pool
// ---------------------------------------------------------------------------

/// A held set of DISTINCT peer connections, refilled toward [`TARGET_PEERS`].
pub struct PeerPool {
    members: RwLock<Vec<Member>>,
    target: usize,
    book: Arc<dyn AddressBook>,
    dialer: Arc<dyn PeerDialer>,
    entropy: Arc<dyn EntropySource>,
    /// The candidate list, resolved on first use and then FIXED for the life of the pool.
    ///
    /// Fixed on purpose: re-resolving per fill would reopen the door #2573 closes, by letting a
    /// resolver that is fast or always-up reappear at the head of every future list.
    addresses: RwLock<Option<Vec<SocketAddr>>>,
}

impl PeerPool {
    /// An empty pool. Nothing is dialled until [`PeerPool::fill`].
    pub fn new(
        book: Arc<dyn AddressBook>,
        dialer: Arc<dyn PeerDialer>,
        entropy: Arc<dyn EntropySource>,
        target: usize,
    ) -> Self {
        Self {
            members: RwLock::new(Vec::new()),
            target,
            book,
            dialer,
            entropy,
            addresses: RwLock::new(None),
        }
    }

    /// The production pool: [`TARGET_PEERS`] members chosen with the OS CSPRNG.
    pub fn mainnet(book: Arc<dyn AddressBook>, dialer: Arc<dyn PeerDialer>) -> Self {
        Self::new(book, dialer, Arc::new(quorum::OsEntropy), TARGET_PEERS)
    }

    /// How many peers are held right now — the honest value for `chia_peer_count`.
    pub async fn len(&self) -> usize {
        self.members.read().await.len()
    }

    /// Whether the pool holds nothing.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Every member, cloned.
    pub async fn members(&self) -> Vec<Member> {
        self.members.read().await.clone()
    }

    /// Dial toward [`PeerPool::target`], admitting each address at most once.
    ///
    /// Returns the number of members held afterwards. Falling short is ordinary and is reported
    /// by that number rather than by an error: a pool with three members is degraded, not
    /// broken, and the caller decides what a shortfall means.
    ///
    /// Candidates are tried in list order and each is dialled at most once per fill, so an
    /// address that answers repeatedly cannot occupy more than one slot. That single rule is
    /// what stops one process supplying a whole quorum (#2573).
    pub async fn fill(&self) -> usize {
        let candidates = self.candidate_addresses().await;

        let mut held: HashSet<SocketAddr> =
            self.members.read().await.iter().map(|m| m.addr).collect();

        for addr in candidates {
            if held.len() >= self.target {
                break;
            }
            if held.contains(&addr) {
                continue;
            }
            let Some(peer) = self.dialer.dial(addr).await else {
                continue;
            };
            let mut members = self.members.write().await;
            // Re-checked under the write lock: a concurrent fill may have admitted this address
            // between the read above and here, and two members at one address is exactly the
            // duplicate the quorum must never see.
            if members.iter().any(|m| m.addr == addr) || members.len() >= self.target {
                continue;
            }
            members.push(Member { addr, peer });
            held.insert(addr);
        }

        self.len().await
    }

    /// Drop a member — a peer that disconnected, or one that proved unusable.
    ///
    /// The slot is not re-dialled here; the supervisor's backoff ladder owns retry timing, and a
    /// refill hidden inside an eviction would dial in a tight loop whenever a hostile peer
    /// disconnects on purpose.
    pub async fn evict(&self, addr: SocketAddr) {
        self.members.write().await.retain(|m| m.addr != addr);
    }

    /// Draw `k` DISTINCT members uniformly at random.
    ///
    /// Uniform over held members via [`quorum::select_sample`]'s partial Fisher-Yates, so no
    /// member gains an advantage from being dialled first — which matters precisely because the
    /// dial order is partly attacker-influenced (a fast, always-up node answers early).
    ///
    /// Returns fewer than `k` only when the pool holds fewer than `k`. The caller must treat a
    /// short sample as [`quorum::Verdict::Insufficient`] rather than lowering the bar.
    pub async fn sample(&self, k: usize) -> Vec<Member> {
        let members = self.members.read().await;
        quorum::select_sample(self.entropy.as_ref(), members.len(), k)
            .into_iter()
            .map(|i| members[i].clone())
            .collect()
    }

    /// The candidate list, resolving it on first use and reusing it thereafter.
    async fn candidate_addresses(&self) -> Vec<SocketAddr> {
        if let Some(cached) = self.addresses.read().await.as_ref() {
            return cached.clone();
        }
        let resolved = self.book.addresses().await;
        let mut slot = self.addresses.write().await;
        // Another filler may have resolved first; keep the winner so the list stays FIXED.
        slot.get_or_insert(resolved).clone()
    }
}

// ---------------------------------------------------------------------------
// Assembling the candidate list (#2573)
// ---------------------------------------------------------------------------

/// Build the pool's candidate list from the three sources, in trust order, de-duplicated.
///
/// Pure, and separated from resolution so the ONE rule #2573 is about — which addresses are
/// allowed in, and on whose authority — is readable and exhaustively testable without DNS.
///
/// * `operator` — `user_managed` rows and `TRUSTED_FULLNODE`: addresses a human named. These go
///   first because an operator who pointed the wallet at their own node must not be quietly
///   routed onto a stranger's.
/// * `discovered` — DNS-introducer answers, ALREADY shuffled by the caller.
///
/// **Loopback gets no special case.** It is admitted if and only if it appears in `operator`,
/// which is the whole of the #2573 fix: `connect_random_peer` prepends `127.0.0.1` to every
/// call, so a co-resident process that wins the race to bind `8444` is returned by every call
/// and can fill a pool by itself. Here it is one candidate among many, and only when asked for.
pub fn assemble_addresses(operator: &[SocketAddr], discovered: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    operator
        .iter()
        .chain(discovered.iter())
        .copied()
        .filter(|addr| seen.insert(*addr))
        .collect()
}

#[cfg(test)]
mod tests;
