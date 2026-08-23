//! The PRODUCTION [`PeerSample`] and [`CoinPeer`]: real Chia full nodes, dialled by this node
//! (dig_ecosystem#3032).
//!
//! # Held between reads, and redrawn on a timer
//!
//! A lineage walk is one round trip per generation, and dialling a fresh quorum for every hop
//! would make a profile read cost dozens of TCP+TLS handshakes. So the sample is DIALLED ONCE and
//! held, and every read puts its question to the peers already connected.
//!
//! Holding a set forever would be the opposite mistake: a fixed set is a set an attacker only has
//! to capture once. NC-12 asks for peers that are periodically CYCLED, so the held sample is
//! redrawn after [`SAMPLE_LIFETIME`] and whenever attrition takes it below
//! [`quorum::CORROBORATION_FLOOR`].
//!
//! # Trust, and what is deliberately not granted
//!
//! Every peer here is dialled through `chia-query`'s discovery and is UNTRUSTED. Nothing sets a
//! `trusted` flag on a dialled peer — that maps to a local-node/trusted classification, which is a
//! custody grant and not something an arbitrary read has any business handing out. A peer earns
//! nothing by being reachable, fast, or first; it is one voice in a tally.
//!
//! Only [`chia_query::peer::connect::PeerOrigin::Discovered`] draws are counted, for the reason
//! [`super::super::sync_supervisor::ChiaQuorumCorroborator`] records: the priority addresses the
//! dialler prefers include the loopback, and a co-resident process is exactly the source a local
//! attacker can supply. It is a good peer to ask and not an independent voice.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chia_protocol::Bytes32;

use super::super::fallback::{FallbackCoin, FallbackCoinSpend};
use super::super::quorum;
use super::super::sync_supervisor::{assemble_distinct_sample, Draw};
use super::super::{Error, Result};
use super::{CoinPeer, PeerSample};

/// How long a dialled sample is used before it is thrown away and redrawn.
///
/// Five minutes: long enough that a profile read and the walk behind it complete on one set of
/// connections, short enough that a captured set does not decide this node's view of the chain for
/// the life of the process. It is the cycling half of NC-12; the corroboration half is the tally.
const SAMPLE_LIFETIME: Duration = Duration::from_secs(300);

/// How long one dial, and one request, may take.
const PEER_TIMEOUT: Duration = Duration::from_secs(15);

/// How many dial attempts one redraw may spend assembling [`quorum::QUORUM_SAMPLE`] distinct peers.
const MAX_DIAL_ATTEMPTS: usize = quorum::QUORUM_SAMPLE * 3;

/// One dialled full node, asked for coins.
pub struct ChiaCoinPeer {
    peer: chia_wallet_sdk::client::Peer,
    /// The address reached — this peer's identity in a tally. Distinctness of these is what makes
    /// four opinions four opinions.
    addr: String,
    genesis_challenge: Bytes32,
    /// Set the moment a request to this peer fails, so the next redraw drops it. A peer is never
    /// banned or accused — it is simply not re-used by a sample that could not reach it.
    failed: AtomicBool,
}

impl ChiaCoinPeer {
    /// This peer's coin state for one id, or `Ok(None)` for its claim that no such coin exists.
    ///
    /// The `false` is `include_spent_coins`-as-subscription: this asks for the coin's state
    /// without subscribing to it, which is what an arbitrary read wants — a subscription would
    /// make every coin a profile walk touches a permanent obligation of the peer.
    async fn coin_state(&self, coin_id: Bytes32) -> Result<Option<chia_protocol::CoinState>> {
        let response = tokio::time::timeout(
            PEER_TIMEOUT,
            self.peer
                .request_coin_state(vec![coin_id], None, self.genesis_challenge, false),
        )
        .await
        .map_err(|_| self.fail("coin-state request timed out"))?
        .map_err(|e| self.fail(&format!("coin-state request failed: {e}")))?
        .map_err(|_| self.fail("coin-state request rejected"))?;

        // An empty list from a SUCCESSFUL response is this peer's claim of absence, which is an
        // answer it is entitled to give — and one the tally, not this peer, decides on.
        Ok(response.coin_states.first().copied())
    }

    /// Mark this peer unusable and describe why. Every failure path goes through here so a peer
    /// cannot be dropped from the pool without the reason being sayable.
    fn fail(&self, why: &str) -> Error {
        self.failed.store(true, Ordering::Relaxed);
        Error::internal(format!("peer {}: {why}", self.addr))
    }
}

#[async_trait]
impl CoinPeer for ChiaCoinPeer {
    fn id(&self) -> String {
        self.addr.clone()
    }

    async fn coin_record(&self, coin_id: Bytes32) -> Result<Option<FallbackCoin>> {
        Ok(self.coin_state(coin_id).await?.map(|state| FallbackCoin {
            // RECOMPUTED from the coin the peer sent, never echoed from the request. A coin id is
            // `SHA256(parent ‖ puzzle_hash ‖ amount)`, so this is what binds the answer to the
            // question: a peer that substitutes a different coin produces a different id and the
            // tally sees a disagreement rather than a swap.
            coin_id: hex::encode(state.coin.coin_id()),
            parent_coin_info: hex::encode(state.coin.parent_coin_info),
            puzzle_hash: hex::encode(state.coin.puzzle_hash),
            amount: state.coin.amount,
            created_height: state.created_height,
            spent_height: state.spent_height,
            // The peer's coin state carries heights, not timestamps. `None` here is "this read
            // never asked", which is the truth; filling it with a zero would date every coin to
            // 1970.
            created_timestamp: None,
            spent_timestamp: None,
        }))
    }

    async fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<FallbackCoinSpend>> {
        // An unknown coin and an unspent coin both genuinely have no spend, and both are this
        // peer's claim rather than a fact — the tally decides.
        let Some(state) = self.coin_state(coin_id).await? else {
            return Ok(None);
        };
        let Some(spent_height) = state.spent_height else {
            return Ok(None);
        };

        let response = tokio::time::timeout(
            PEER_TIMEOUT,
            self.peer.request_puzzle_and_solution(coin_id, spent_height),
        )
        .await
        .map_err(|_| self.fail("puzzle-and-solution request timed out"))?
        .map_err(|e| self.fail(&format!("puzzle-and-solution request failed: {e}")))?
        .map_err(|_| self.fail("puzzle-and-solution request rejected"))?;

        // The reveal is CHECKED against the coin's own puzzle hash before it leaves this peer's
        // hands, and the check is local: a puzzle hash IS the reveal's CLVM tree hash. It happens
        // HERE, per peer, rather than after the tally, because a peer that sends an unverifiable
        // program must be excluded from the round — folding it in as a voter would let three
        // honest peers carry a forged fourth answer into a majority.
        let puzzle_hash = hex::encode(state.coin.puzzle_hash);
        let puzzle_reveal = super::super::fallback::verified_reveal_hex(
            &hex::encode(response.puzzle),
            &puzzle_hash,
        )
        .map_err(|e| self.fail(&e.message))?;

        // The COIN comes from the coin-state read, not from the puzzle response: the peer's
        // `PuzzleSolutionResponse` carries only a coin name, so a spend built from it alone would
        // hash to the wrong id and fail every caller's binding check.
        Ok(Some(FallbackCoinSpend {
            coin_id: hex::encode(state.coin.coin_id()),
            parent_coin_info: hex::encode(state.coin.parent_coin_info),
            puzzle_hash,
            amount: state.coin.amount,
            puzzle_reveal,
            solution: hex::encode(response.solution),
        }))
    }
}

/// The held sample and when it was drawn.
struct Held {
    peers: Vec<Arc<ChiaCoinPeer>>,
    drawn_at: Instant,
}

/// A [`PeerSample`] of real, independently discovered full nodes, held between reads and cycled.
pub struct DialedPeerSample {
    network: chia_query::NetworkType,
    genesis_challenge: Bytes32,
    held: tokio::sync::Mutex<Option<Held>>,
}

impl DialedPeerSample {
    /// A mainnet sample.
    pub fn mainnet() -> Self {
        Self {
            network: chia_query::NetworkType::Mainnet,
            genesis_challenge: chia_wallet_sdk::types::MAINNET_CONSTANTS.genesis_challenge,
            held: tokio::sync::Mutex::new(None),
        }
    }

    /// Whether the held sample may still be used: young enough, and **not narrowed at all**.
    ///
    /// # Why any attrition forces a redraw, rather than attrition down to the floor
    ///
    /// `failed` is sticky and monotone, so within one [`SAMPLE_LIFETIME`] a sample only ever loses
    /// members. Tolerating loss down to [`quorum::CORROBORATION_FLOOR`] lets an attacker CHOOSE the
    /// quorum: honest peers that hiccup once are dropped permanently while peers that always answer
    /// never are, so a four-peer sample ratchets to the two peers most eager to reply — and two is a
    /// full quorum, since `required_agreement(2) == 2`. Forcing that attrition is cheap, because the
    /// endpoint feeding these reads is token-less.
    ///
    /// So the bar is the size the sample was DRAWN at. Losing a peer costs a redraw, which is a few
    /// dials; the alternative costs the property the whole module exists for. A narrowing sample is
    /// exactly when fresh peers are most needed, and the old rule kept them out at that moment.
    fn still_usable(held: &Held) -> bool {
        let live = held
            .peers
            .iter()
            .filter(|p| !p.failed.load(Ordering::Relaxed))
            .count();
        held.drawn_at.elapsed() < SAMPLE_LIFETIME
            && live >= held.peers.len()
            && live >= quorum::CORROBORATION_FLOOR
    }

    /// Dial up to [`quorum::QUORUM_SAMPLE`] distinct, independently discovered peers.
    async fn redraw(&self) -> Vec<Arc<ChiaCoinPeer>> {
        // Generated in memory, never file-backed: a node running as a Windows service has no
        // readable `~/.chia`, and a full node accepts any well-formed client certificate.
        let Ok(tls) = chia_query::peer::connect::create_generated_tls() else {
            return Vec::new();
        };
        let tls = &tls;

        let drawn = assemble_distinct_sample(
            quorum::QUORUM_SAMPLE,
            MAX_DIAL_ATTEMPTS,
            |exclude: Vec<std::net::SocketAddr>| async move {
                let (peer, addr, _receiver, origin) =
                    chia_query::peer::connect::connect_random_peer_excluding(
                        self.network,
                        tls,
                        PEER_TIMEOUT,
                        &exclude,
                    )
                    .await
                    .ok()?;
                Some(Draw {
                    addr,
                    origin,
                    member: peer,
                })
            },
        )
        .await;

        drawn
            .into_iter()
            .map(|(addr, peer)| {
                Arc::new(ChiaCoinPeer {
                    peer,
                    addr: addr.to_string(),
                    genesis_challenge: self.genesis_challenge,
                    failed: AtomicBool::new(false),
                })
            })
            .collect()
    }
}

#[async_trait]
impl PeerSample for DialedPeerSample {
    async fn draw(&self) -> Vec<Arc<dyn CoinPeer>> {
        let mut slot = self.held.lock().await;
        let usable = slot.as_ref().is_some_and(Self::still_usable);
        if !usable {
            *slot = Some(Held {
                peers: self.redraw().await,
                drawn_at: Instant::now(),
            });
        }
        slot.as_ref()
            .map(|held| {
                held.peers
                    .iter()
                    .filter(|p| !p.failed.load(Ordering::Relaxed))
                    .map(|p| p.clone() as Arc<dyn CoinPeer>)
                    .collect()
            })
            .unwrap_or_default()
    }
}
