//! `dig-node peers` — view + manage the node's peer connections from the CLI (#559).
//!
//! Parity with the DIG Chrome extension's peer surface (`src/features/peers/peersApi.ts`):
//! the node OWNS peer management (dig-nat + dig-gossip's `AddressManager`); the CLI, like the
//! extension, is a THIN frontend driving it over the token-gated `control.*` RPC surface via
//! the shared [`crate::control_client::call_control`] client (master-token auth over loopback).
//!
//! Subcommands (see `entrypoint.rs`):
//!   * `dig-node peers` / `peers list` — the live peer status: running flag, connected count,
//!     relay reservation, and (when a newer node fills them) the per-peer list — addresses
//!     shown IPv6-FIRST per the ecosystem §5.2 address-family policy.
//!   * `dig-node peers connect <peer>` — dial a peer by address or peer_id.
//!   * `dig-node peers disconnect <peer>` — drop a connected peer.
//!   * `dig-node peers ban <peer> --state <ban|blacklist|none>` — block / soft-block / clear a peer.
//!   * `dig-node peers pool-config --max-connections <n>` — set the peer-pool connection cap.
//!
//! # Node-side gap (cross-repo follow-up, flagged NOT fixed here)
//!
//! Today the node implements ONLY `control.peerStatus` (a running flag + a connected COUNT); it
//! does not yet return a per-peer list, nor implement the management RPCs
//! (`control.peers.connect`/`disconnect`/`setBan`/`setPoolConfig`) — the SAME gap the extension
//! documents. So the `list` view degrades honestly (count only) and the management verbs return
//! the node's METHOD_NOT_FOUND until the node ships those methods. The CLI verbs exist now so the
//! surface reaches parity and lights up with no CLI change once the node implements them.

use serde_json::{json, Value};

use crate::cli::Outcome;
use crate::config::Config;
use crate::control_client::call_control;

/// A peer-ban state — soft (blacklist), hard (ban), or cleared (none). Mirrors the extension's
/// `BanState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanState {
    /// Refuse connections from the peer (hard block).
    Ban,
    /// Do not dial/prefer the peer (soft block).
    Blacklist,
    /// Clear any ban/blacklist.
    None,
}

impl BanState {
    /// The wire token sent as `params.state` (matches the extension's `control.peers.setBan`).
    fn as_str(self) -> &'static str {
        match self {
            BanState::Ban => "ban",
            BanState::Blacklist => "blacklist",
            BanState::None => "none",
        }
    }

    /// Parse the `--state` flag value; `Err` names the accepted tokens (USAGE).
    pub fn parse(s: &str) -> Result<BanState, String> {
        match s {
            "ban" => Ok(BanState::Ban),
            "blacklist" => Ok(BanState::Blacklist),
            "none" => Ok(BanState::None),
            other => Err(format!(
                "invalid ban state {other:?} — expected one of: ban, blacklist, none"
            )),
        }
    }
}

/// One `peers` action, clap-agnostic (mapped from the subcommand in `entrypoint.rs`).
pub enum PeersAction {
    /// List the live peer status (the default `dig-node peers`).
    List,
    /// Dial a peer by address or peer_id.
    Connect { peer: String },
    /// Drop a connected peer.
    Disconnect { peer: String },
    /// Block / soft-block / clear a peer.
    SetBan { peer: String, state: BanState },
    /// Set the peer-pool max-connections cap.
    SetPoolConfig { max_connections: u32 },
}

/// Run a `peers` subcommand: dispatch the mapped `control.*` method and render an [`Outcome`].
pub fn run(config: &Config, action: PeersAction) -> std::io::Result<Outcome> {
    match action {
        PeersAction::List => {
            let result = call_control(config, "control.peerStatus", json!({}))?;
            Ok(Outcome::new(format_status(&result), result))
        }
        PeersAction::Connect { peer } => {
            let result = call_control(config, "control.peers.connect", json!({ "peer": peer }))?;
            Ok(Outcome::new(
                format!("dig-node: dialing peer {peer}"),
                result,
            ))
        }
        PeersAction::Disconnect { peer } => {
            let result = call_control(config, "control.peers.disconnect", json!({ "peer": peer }))?;
            Ok(Outcome::new(
                format!("dig-node: disconnected peer {peer}"),
                result,
            ))
        }
        PeersAction::SetBan { peer, state } => {
            let result = call_control(
                config,
                "control.peers.setBan",
                json!({ "peer": peer, "state": state.as_str() }),
            )?;
            Ok(Outcome::new(
                format!("dig-node: set ban state {} for peer {peer}", state.as_str()),
                result,
            ))
        }
        PeersAction::SetPoolConfig { max_connections } => {
            let result = call_control(
                config,
                "control.peers.setPoolConfig",
                json!({ "max_connections": max_connections }),
            )?;
            Ok(Outcome::new(
                format!("dig-node: set peer-pool max_connections to {max_connections}"),
                result,
            ))
        }
    }
}

/// Render `control.peerStatus` as an operator-friendly summary. Shows the running flag, the
/// connected count, and the relay reservation; when a newer node fills the optional per-peer
/// list it prints each peer with its addresses ordered IPv6-first (§5.2).
fn format_status(result: &Value) -> String {
    let running = result["running"].as_bool().unwrap_or(false);
    if !running {
        return "dig-node: peer network is not running (no connected peers).".to_string();
    }
    let mut out = format!(
        "dig-node peer network: running · {} connected peer(s)",
        result["connected_peers"].as_u64().unwrap_or(0),
    );
    if let Some(url) = result["relay"]["url"].as_str() {
        let reserved = result["relay"]["reserved"].as_bool().unwrap_or(false);
        out.push_str(&format!(
            "\n  relay {url} — reservation {}",
            if reserved { "held" } else { "none" }
        ));
    }
    let peers = result["peers"].as_array().cloned().unwrap_or_default();
    if peers.is_empty() {
        // Honest degradation: today's node reports a count but not a per-peer list.
        out.push_str(
            "\n  (this node build reports a count only — a per-peer list needs a newer node)",
        );
    } else {
        out.push_str("\n  peers:");
        for p in &peers {
            out.push_str(&format!("\n    • {}", format_peer(p)));
        }
    }
    out
}

/// One peer line: `peer_id  type/direction  addr, addr` with addresses IPv6-first (§5.2).
fn format_peer(p: &Value) -> String {
    let id = p["peer_id"].as_str().unwrap_or("?");
    let ty = p["connection_type"].as_str().unwrap_or("?");
    let dir = p["direction"].as_str().unwrap_or("?");
    let addrs = ipv6_first_addrs(p);
    let addrs = if addrs.is_empty() {
        "(no address)".to_string()
    } else {
        addrs.join(", ")
    };
    format!("{id}  {ty}/{dir}  {addrs}")
}

/// A peer's addresses ordered IPv6-FIRST, IPv4 second (§5.2 display policy). PURE.
fn ipv6_first_addrs(p: &Value) -> Vec<String> {
    let mut addrs: Vec<String> = p["addresses"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    // IPv6 literals contain ':' inside brackets; IPv4 do not. Stable sort by "is IPv4" so the
    // relative order within each family is preserved but IPv6 sorts ahead.
    addrs.sort_by_key(|a| is_ipv4(a));
    addrs
}

/// Heuristic: does this address string look IPv4 (dotted quad, no bracketed IPv6)? PURE.
fn is_ipv4(addr: &str) -> bool {
    !addr.contains('[') && addr.matches('.').count() >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_state_parses_and_rejects() {
        assert_eq!(BanState::parse("ban").unwrap(), BanState::Ban);
        assert_eq!(BanState::parse("blacklist").unwrap(), BanState::Blacklist);
        assert_eq!(BanState::parse("none").unwrap(), BanState::None);
        assert!(BanState::parse("nope").is_err());
    }

    #[test]
    fn not_running_status_reads_clearly() {
        let s = format_status(&json!({ "running": false }));
        assert!(s.contains("not running"));
    }

    #[test]
    fn running_status_reports_count_and_relay() {
        let s = format_status(&json!({
            "running": true,
            "connected_peers": 4,
            "relay": { "url": "wss://relay.dig.net:9450", "reserved": true },
        }));
        assert!(s.contains("4 connected peer"));
        assert!(s.contains("relay.dig.net"));
        assert!(s.contains("reservation held"));
        // No per-peer list today → the honest degradation note appears.
        assert!(s.contains("newer node"));
    }

    #[test]
    fn ipv6_addresses_sort_before_ipv4() {
        let peer = json!({
            "peer_id": "abc",
            "addresses": ["1.2.3.4:9444", "[2001:db8::1]:9444", "5.6.7.8:9444"],
        });
        let ordered = ipv6_first_addrs(&peer);
        assert_eq!(ordered[0], "[2001:db8::1]:9444", "IPv6 comes first (§5.2)");
        assert_eq!(ordered[1], "1.2.3.4:9444");
        assert_eq!(ordered[2], "5.6.7.8:9444");
    }

    #[test]
    fn peer_line_shows_id_type_direction_and_ipv6_first() {
        let peer = json!({
            "peer_id": "deadbeef",
            "connection_type": "direct",
            "direction": "outbound",
            "addresses": ["9.9.9.9:1", "[fe80::1]:2"],
        });
        let line = format_peer(&peer);
        assert!(line.contains("deadbeef"));
        assert!(line.contains("direct/outbound"));
        // IPv6 precedes IPv4 in the rendered address list.
        let v6 = line.find("[fe80::1]:2").unwrap();
        let v4 = line.find("9.9.9.9:1").unwrap();
        assert!(v6 < v4, "IPv6 address must render before IPv4");
    }

    #[test]
    fn running_status_with_peer_list_renders_each_peer() {
        let s = format_status(&json!({
            "running": true,
            "connected_peers": 1,
            "peers": [{
                "peer_id": "p1",
                "connection_type": "relayed",
                "direction": "inbound",
                "addresses": ["[2001:db8::9]:9444"],
            }],
        }));
        assert!(s.contains("peers:"));
        assert!(s.contains("p1"));
        assert!(s.contains("relayed/inbound"));
        assert!(
            !s.contains("newer node"),
            "a filled list omits the degradation note"
        );
    }
}
