//! The production [`AddressBook`] and [`PeerDialer`]: real DNS introducers and real
//! `chia-wallet-sdk` peer connections (dig_ecosystem#2606, #2573).
//!
//! Kept apart from the pool itself because everything here needs a network or a database, and
//! the pool's rules — distinctness, resolve-once, uniform sampling — must stay testable without
//! either.
//!
//! # Why this does not call `connect_random_peer`
//!
//! `chia_query::peer::connect::connect_random_peer` bundles three decisions the pool has to make
//! for itself: it prepends `127.0.0.1` unconditionally, it resolves introducers afresh on every
//! call, and it returns whichever address answers FIRST. Those are reasonable for a caller that
//! wants *a* peer; for a caller filling five slots they mean five calls can return one peer, and
//! selection is decided by latency, which an attacker running a fast always-up node controls.
//! So the pool takes the two halves separately — resolve a LIST here, dial a CHOSEN address here
//! — and keeps the choosing to itself.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chia_protocol::Bytes32;
use chia_wallet_sdk::client::{connect_peer, Connector, Network, Peer, PeerOptions};
use tokio::sync::mpsc;

use super::{AddressBook, PeerDialer, PoolPeer};
use crate::sage::db::WalletDb;
use crate::sage::quorum::PeakClaim;

/// How many introducer lookups run concurrently, and how many addresses one batch resolves.
const LOOKUP_BATCH: usize = 30;

// ---------------------------------------------------------------------------
// The address book
// ---------------------------------------------------------------------------

/// Operator-named addresses first, then DNS-introducer answers.
///
/// The operator half is read from the `peers` table on resolution rather than passed in, because
/// the pool resolves its list once and lazily — by which time a peer row added during start-up is
/// present, which a list captured at construction would have missed.
pub struct DbAddressBook {
    db: WalletDb,
    network: Network,
    lookup_timeout: Duration,
    default_port: u16,
}

impl DbAddressBook {
    /// A mainnet book over `db`'s `user_managed` peer rows plus mainnet's DNS introducers.
    pub fn mainnet(db: WalletDb, lookup_timeout: Duration) -> Self {
        Self {
            db,
            network: Network::default_mainnet(),
            lookup_timeout,
            default_port: crate::sage::network::DEFAULT_PEER_PORT as u16,
        }
    }
}

#[async_trait::async_trait]
impl AddressBook for DbAddressBook {
    async fn addresses(&self) -> Vec<SocketAddr> {
        let rows = self.db.all_peers().await.unwrap_or_default();
        let operator = operator_addresses(
            rows.into_iter()
                .filter(|row| row.user_managed)
                .map(|row| (row.ip_addr, row.port as u16)),
            std::env::var("TRUSTED_FULLNODE").ok().as_deref(),
            self.default_port,
        );

        let discovered = self
            .network
            .lookup_all(self.lookup_timeout, LOOKUP_BATCH)
            .await;

        super::assemble_addresses(&operator, &discovered)
    }
}

/// The operator's addresses: `TRUSTED_FULLNODE`, then every `user_managed` row.
///
/// This is the ONLY door loopback can come through (#2573). An operator running a full node on
/// the same host adds a `127.0.0.1` peer row and gets exactly what they asked for; a co-resident
/// process that merely won the race to bind `8444` gets nothing.
pub fn operator_addresses(
    user_managed: impl IntoIterator<Item = (String, u16)>,
    trusted_fullnode: Option<&str>,
    default_port: u16,
) -> Vec<SocketAddr> {
    let trusted = trusted_fullnode
        .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, default_port));

    trusted
        .into_iter()
        .chain(user_managed.into_iter().filter_map(|(ip, port)| {
            ip.parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, port))
        }))
        .collect()
}

// ---------------------------------------------------------------------------
// The dialer
// ---------------------------------------------------------------------------

/// Dials one chosen address over the generated-in-memory TLS identity.
///
/// The identity is generated rather than file-backed because a node running as a Windows service
/// has no readable `~/.chia`, and a full node accepts any well-formed client certificate
/// (dig_ecosystem#2210).
pub struct ChiaDialer {
    network_id: String,
    tls: Connector,
    timeout: Duration,
}

impl ChiaDialer {
    /// A dialer for `network_id`, using `tls` for every connection.
    pub fn new(network_id: String, tls: Connector, timeout: Duration) -> Self {
        Self {
            network_id,
            tls,
            timeout,
        }
    }
}

#[async_trait::async_trait]
impl PeerDialer for ChiaDialer {
    async fn dial(&self, addr: SocketAddr) -> Option<Arc<dyn PoolPeer>> {
        let connected = tokio::time::timeout(
            self.timeout,
            connect_peer(
                self.network_id.clone(),
                self.tls.clone(),
                addr,
                PeerOptions::default(),
            ),
        )
        .await;

        match connected {
            Ok(Ok((peer, receiver))) => Some(Arc::new(ChiaPoolPeer::new(peer, receiver))),
            Ok(Err(e)) => {
                tracing::debug!(%addr, error = %e, "peer pool: dial refused");
                None
            }
            Err(_) => {
                tracing::debug!(%addr, "peer pool: dial timed out");
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// A held connection
// ---------------------------------------------------------------------------

/// One held peer, tracking ITS OWN latest peak claim.
///
/// Per-peer, deliberately. `chia_query`'s pool folds every member's `new_peak_wallet` into one
/// shared `fetch_max`, which is right for "how high is the chain" and wrong for corroboration:
/// it would let the single highest claim — an attacker's, for free, since a claim is unverifiable
/// — become every member's claim, and the quorum would then compare one number with itself four
/// times. Here each member answers only for itself.
struct ChiaPoolPeer {
    peer: Peer,
    peak: Arc<std::sync::RwLock<Option<PeakClaim>>>,
}

impl ChiaPoolPeer {
    fn new(peer: Peer, receiver: mpsc::Receiver<chia_protocol::Message>) -> Self {
        let peak = Arc::new(std::sync::RwLock::new(None));
        spawn_peak_tracker(Arc::clone(&peak), receiver);
        Self { peer, peak }
    }
}

#[async_trait::async_trait]
impl PoolPeer for ChiaPoolPeer {
    fn peak(&self) -> Option<PeakClaim> {
        *self.peak.read().expect("peak lock poisoned")
    }

    async fn header_hash_at(&self, height: u32) -> Option<Bytes32> {
        use chia_protocol::{RejectHeaderRequest, RequestBlockHeader, RespondBlockHeader};

        // SELF-VERIFYING: the hash is COMPUTED from the block the peer sent — `header_hash()`
        // folds the block's own foliage — never read from a field the peer chose. A peer cannot
        // name a hash that does not belong to the block it handed over; it can only send a
        // different block, which is precisely the claim the quorum then votes on.
        match self
            .peer
            .request_fallible::<RespondBlockHeader, RejectHeaderRequest, _>(
                RequestBlockHeader::new(height),
            )
            .await
        {
            Ok(Ok(respond)) => Some(respond.header_block.header_hash()),
            Ok(Err(_rejected)) => None,
            Err(e) => {
                tracing::debug!(error = %e, height, "peer pool: header request failed");
                None
            }
        }
    }
}

/// Keep `peak` current from this peer's `new_peak_wallet` announcements until it disconnects.
fn spawn_peak_tracker(
    peak: Arc<std::sync::RwLock<Option<PeakClaim>>>,
    mut receiver: mpsc::Receiver<chia_protocol::Message>,
) {
    tokio::spawn(async move {
        while let Some(message) = receiver.recv().await {
            if message.msg_type != chia_protocol::ProtocolMessageTypes::NewPeakWallet {
                continue;
            }
            let Ok(announced) = <chia_protocol::NewPeakWallet as chia_traits::Streamable>::from_bytes(
                &message.data,
            ) else {
                continue;
            };
            // Last-write-wins rather than max: a peer's CURRENT claim is what corroboration
            // judges it on, and a peer that reorgs downward must be allowed to say so.
            *peak.write().expect("peak lock poisoned") = Some(PeakClaim {
                height: announced.height,
                header_hash: announced.header_hash,
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const LOOPBACK: &str = "127.0.0.1";

    /// The #2573 property at the door loopback must come through: with no operator input, the
    /// operator list is EMPTY — nothing prepends loopback on its own.
    #[test]
    fn no_operator_input_yields_no_addresses_at_all() {
        assert!(operator_addresses(Vec::new(), None, 8444).is_empty());
    }

    /// A `user_managed` row naming loopback is honoured — the escape hatch for an operator
    /// running their own node beside the wallet.
    #[test]
    fn a_user_managed_loopback_row_is_honoured() {
        let list = operator_addresses(vec![(LOOPBACK.to_string(), 8444)], None, 8444);
        assert_eq!(
            list,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8444)]
        );
    }

    /// `TRUSTED_FULLNODE` outranks the peer rows, matching the order `connect_random_peer` used.
    #[test]
    fn trusted_fullnode_comes_before_the_peer_rows() {
        let list = operator_addresses(
            vec![("203.0.113.1".to_string(), 8444)],
            Some("203.0.113.9"),
            8444,
        );
        assert_eq!(list[0].ip().to_string(), "203.0.113.9");
        assert_eq!(list.len(), 2);
    }

    /// An unparseable address is dropped rather than defaulting to anything — a malformed row
    /// must never silently become loopback.
    #[test]
    fn an_unparseable_address_is_dropped_not_defaulted() {
        let list = operator_addresses(
            vec![("not-an-ip".to_string(), 8444)],
            Some("also-not-an-ip"),
            8444,
        );
        assert!(list.is_empty());
    }
}
