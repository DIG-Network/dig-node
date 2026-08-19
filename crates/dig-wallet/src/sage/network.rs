//! Peers + network/sync settings (design A.5 "Network / peers / settings", #205 PR4):
//! `get_peers`/`add_peer`/`remove_peer`, `set_discover_peers`/`set_target_peers`,
//! `set_network`/`set_network_override`/`get_networks`/`get_network`, `set_delta_sync`/
//! `set_delta_sync_override`, `set_change_address`.
//!
//! Peers are DB-backed (§18.16): `add_peer` persists a user-managed entry (mirroring Sage,
//! which keeps manually-added peers across restarts); `peak_height` reports `None` —
//! UNOBSERVED — until this node's live per-peer telemetry is wired to the sync loop, and is
//! never fabricated. The known network list is the two DIG/Chia networks this wallet backend
//! can sync against (design Part B): mainnet and testnet11.

use super::db::WalletDb;
use super::types::{Network, NetworkKind, NetworkList, PeerRecord};
use super::Result;

/// The standard Chia full-node peer port (design B.1) — the port `add_peer` assumes when the
/// caller supplies only an IP (Sage's `add_peer` request shape carries no port either).
pub const DEFAULT_PEER_PORT: i64 = 8444;

/// `get_peers` — EVERY tracked peer: trusted, discovered and banned alike.
///
/// Banned entries are included because this is the only enumeration of them, and a blocklist a
/// person cannot read is a blocklist they cannot correct. Read `banned` to tell them apart; the
/// DIALLING path is [`super::db::WalletDb::unbanned_peers`] and is deliberately a different read.
///
/// `peak_height` is reported as `None` — UNOBSERVED — rather than as the `0` the column holds. No
/// writer sets a peak height yet (SPEC §18.16: never fabricated), so `0` here means "nobody has
/// polled this peer", and rendering that as a height would show every trusted peer stalled at
/// genesis. That is the one signal an operator has for judging whether a peer they believe
/// WITHOUT corroboration is current, so a stuck-looking peer and an unpolled one must not read the
/// same. When telemetry is wired, the column has to become nullable so a genuine genesis height
/// stays distinguishable from an absent one.
pub async fn get_peers(db: &WalletDb) -> Result<Vec<PeerRecord>> {
    let rows = db.all_peers_including_banned().await?;
    Ok(rows
        .into_iter()
        .map(|r| PeerRecord {
            ip_addr: r.ip_addr,
            port: r.port as u16,
            peak_height: (r.peak_height > 0).then_some(r.peak_height as u32),
            user_managed: r.user_managed,
            banned: r.banned,
        })
        .collect())
}

/// `add_peer` — add (or un-ban) a user-managed peer at the standard full-node port.
///
/// Returns whether the peer ended up TRUSTED, which is not the same as whether the call succeeded:
/// adding a peer that was banned un-bans it without granting the corroboration bypass. See
/// [`super::db::WalletDb::add_peer`].
pub async fn add_peer(db: &WalletDb, ip: &str) -> Result<bool> {
    Ok(db.add_peer(ip, DEFAULT_PEER_PORT).await?)
}

/// `remove_peer` — remove a peer, or ban it (excluded from dialling but not forgotten).
///
/// Returns whether an entry MATCHED, so the caller can report un-trusting nothing as the failure
/// to act that it is.
pub async fn remove_peer(db: &WalletDb, ip: &str, ban: bool) -> Result<bool> {
    Ok(db.remove_peer(ip, ban).await?)
}

/// `set_discover_peers`.
pub async fn set_discover_peers(db: &WalletDb, on: bool) -> Result<()> {
    db.set_discover_peers(on).await?;
    Ok(())
}

/// `set_target_peers`.
pub async fn set_target_peers(db: &WalletDb, n: u32) -> Result<()> {
    db.set_target_peers(n).await?;
    Ok(())
}

/// `set_network` / `set_network_override` — both set the wallet's active-network override
/// (one active wallet key in this backend; a per-fingerprint override is a follow-on for
/// multi-key support).
pub async fn set_network(db: &WalletDb, name: Option<&str>) -> Result<()> {
    db.set_network_override(name).await?;
    Ok(())
}

/// The two networks this wallet backend can sync against (design Part B).
fn known_networks() -> NetworkList {
    let mut networks = std::collections::BTreeMap::new();
    networks.insert(
        "mainnet".to_string(),
        Network {
            name: "mainnet".into(),
            ticker: "XCH".into(),
            address_prefix: "xch".into(),
            precision: 12,
            default_port: 8444,
        },
    );
    networks.insert(
        "testnet11".to_string(),
        Network {
            name: "testnet11".into(),
            ticker: "TXCH".into(),
            address_prefix: "txch".into(),
            precision: 12,
            default_port: 58444,
        },
    );
    NetworkList { networks }
}

/// `get_networks` — the known network list.
pub fn get_networks() -> NetworkList {
    known_networks()
}

/// `get_network` — the currently-active network (the wallet's configured `network_id`,
/// unless overridden via `set_network`/`set_network_override`) + its kind.
pub async fn get_network(
    db: &WalletDb,
    configured_network_id: &str,
) -> Result<(Network, NetworkKind)> {
    let settings = db.network_settings().await?;
    let id = settings
        .network_override
        .as_deref()
        .unwrap_or(configured_network_id);
    let networks = known_networks();
    let network = networks
        .networks
        .get(id)
        .cloned()
        .unwrap_or_else(|| networks.networks["mainnet"].clone());
    let kind = if network.name == "mainnet" {
        NetworkKind::Mainnet
    } else {
        NetworkKind::Testnet
    };
    Ok((network, kind))
}

/// `set_delta_sync`.
pub async fn set_delta_sync(db: &WalletDb, on: bool) -> Result<()> {
    db.set_delta_sync(on).await?;
    Ok(())
}

/// `set_delta_sync_override`.
pub async fn set_delta_sync_override(db: &WalletDb, on: Option<bool>) -> Result<()> {
    db.set_delta_sync_override(on).await?;
    Ok(())
}

/// `set_change_address`.
pub async fn set_change_address(db: &WalletDb, address: Option<&str>) -> Result<()> {
    db.set_change_address(address).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_get_remove_peer_round_trip() {
        let db = WalletDb::open_in_memory().await.unwrap();
        add_peer(&db, "9.9.9.9").await.unwrap();
        let peers = get_peers(&db).await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ip_addr, "9.9.9.9");
        assert_eq!(peers[0].port, DEFAULT_PEER_PORT as u16);
        assert!(peers[0].user_managed);
        assert_eq!(
            peers[0].peak_height, None,
            "nobody has polled this peer, so its peak is UNOBSERVED -- reporting 0 would show a \
             peer the operator trusts without corroboration as stalled at genesis"
        );

        remove_peer(&db, "9.9.9.9", false).await.unwrap();
        assert!(get_peers(&db).await.unwrap().is_empty());
    }

    #[test]
    fn get_networks_lists_mainnet_and_testnet11() {
        let list = get_networks();
        assert!(list.networks.contains_key("mainnet"));
        assert!(list.networks.contains_key("testnet11"));
        assert_eq!(list.networks["mainnet"].ticker, "XCH");
        assert_eq!(list.networks["testnet11"].ticker, "TXCH");
    }

    #[tokio::test]
    async fn get_network_defaults_to_configured_id_then_respects_override() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let (network, kind) = get_network(&db, "mainnet").await.unwrap();
        assert_eq!(network.name, "mainnet");
        assert_eq!(kind, NetworkKind::Mainnet);

        set_network(&db, Some("testnet11")).await.unwrap();
        let (network, kind) = get_network(&db, "mainnet").await.unwrap();
        assert_eq!(network.name, "testnet11");
        assert_eq!(kind, NetworkKind::Testnet);
    }

    #[tokio::test]
    async fn settings_setters_persist() {
        let db = WalletDb::open_in_memory().await.unwrap();
        set_discover_peers(&db, false).await.unwrap();
        set_target_peers(&db, 12).await.unwrap();
        set_delta_sync(&db, false).await.unwrap();
        set_delta_sync_override(&db, Some(true)).await.unwrap();
        set_change_address(&db, Some("xch1abc")).await.unwrap();

        let s = db.network_settings().await.unwrap();
        assert!(!s.discover_peers);
        assert_eq!(s.target_peers, 12);
        assert!(!s.delta_sync);
        assert_eq!(s.delta_sync_override, Some(true));
        assert_eq!(s.change_address.as_deref(), Some("xch1abc"));
    }
}
