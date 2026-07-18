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
//! # Node-side coverage + remaining gap
//!
//! The node now returns the per-peer list — `control.peerStatus` emits a `peers[]` array of
//! `{peer_id, address, via, direction}` (rendered IPv6-first below) — and implements
//! `control.peers.connect` (dial a peer into the pool, #929). The remaining management RPCs
//! (`control.peers.disconnect`/`setBan`/`setPoolConfig`) are still a node-side gap (the SAME gap the
//! extension documents): those verbs return the node's METHOD_NOT_FOUND until the node ships them.
//! The CLI verbs exist now so the surface reaches parity and each lights up with no CLI change once
//! the node implements it.

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
    let mut peers = result["peers"].as_array().cloned().unwrap_or_default();
    if peers.is_empty() {
        // Honest degradation: no per-peer list (no peer network running, or an older node build).
        out.push_str(
            "\n  (this node build reports a count only — a per-peer list needs a newer node)",
        );
    } else {
        // Render peers with IPv6-addressed ones first (§5.2 display policy).
        peers.sort_by_key(|p| is_ipv4(p["address"].as_str().unwrap_or("")));
        out.push_str("\n  peers:");
        for p in &peers {
            out.push_str(&format!("\n    • {}", format_peer(p)));
        }
    }
    out
}

/// One peer line: `peer_id  via/direction  address` (the per-peer `{peer_id, address, via, direction}`
/// shape the node's `control.peerStatus` emits — #929).
fn format_peer(p: &Value) -> String {
    let id = p["peer_id"].as_str().unwrap_or("?");
    let via = p["via"].as_str().unwrap_or("?");
    let dir = p["direction"].as_str().unwrap_or("?");
    let addr = p["address"].as_str().unwrap_or("(no address)");
    format!("{id}  {via}/{dir}  {addr}")
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
            "relay": { "url": "wss://relay.dig.net:443", "reserved": true },
        }));
        assert!(s.contains("4 connected peer"));
        assert!(s.contains("relay.dig.net"));
        assert!(s.contains("reservation held"));
        // No per-peer list today → the honest degradation note appears.
        assert!(s.contains("newer node"));
    }

    #[test]
    fn peer_line_shows_id_via_direction_and_address() {
        let peer = json!({
            "peer_id": "deadbeef",
            "via": "direct",
            "direction": "outbound",
            "address": "[fe80::1]:2",
        });
        let line = format_peer(&peer);
        assert!(line.contains("deadbeef"));
        assert!(line.contains("direct/outbound"));
        assert!(line.contains("[fe80::1]:2"));
    }

    #[test]
    fn peer_list_renders_ipv6_peers_before_ipv4() {
        let s = format_status(&json!({
            "running": true,
            "connected_peers": 2,
            "peers": [
                {"peer_id": "v4", "via": "direct", "direction": "outbound", "address": "1.2.3.4:9444"},
                {"peer_id": "v6", "via": "relay", "direction": "inbound", "address": "[2001:db8::9]:9444"},
            ],
        }));
        assert!(s.contains("peers:"));
        // The IPv6-addressed peer renders before the IPv4 one (§5.2).
        let v6 = s.find("v6").unwrap();
        let v4 = s.find("v4").unwrap();
        assert!(v6 < v4, "IPv6-addressed peer must render first");
        assert!(
            !s.contains("newer node"),
            "a filled list omits the degradation note"
        );
    }
}
