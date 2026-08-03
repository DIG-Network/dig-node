//! `control.peers.ping` — the connection-ladder diagnostic (dig_ecosystem#1985).
//!
//! Answers "is this peer actually reachable, and HOW?" by dialing it one ladder rung at a time and
//! reporting every rung, not just the winner. The judgment lives in
//! [`dig_node_core::seams::dig_peer::ping`] — the ladder order, the grading, the identity check, the
//! anti-amplification gate. This module is the SHELL half: parse the params, resolve the node's
//! live pool into the "who is where" list, and map the engine's outcomes onto the control-plane
//! envelope.
//!
//! # Why this is shell-owned rather than delegated to the node's own dispatcher
//!
//! The delegated `control.*` methods (`control.peers.connect`, `control.subscribe`, …) are matched
//! on the `Method` enum in the external `dig-rpc-protocol` crate, so adding one there means
//! releasing that crate first (release-first, `CLAUDE.md` §4.1). Ping needs no wire-contract change
//! between NODES — it is a purely local operator diagnostic — so it is owned here, where adding it
//! costs no cross-crate release. Everything it acts on still lives on the node.

use std::time::Duration;

use dig_node_core::seams::dig_peer::ping;
use dig_node_core::seams::dig_peer::PeerNetwork;
use serde_json::Value;

use crate::control::{control_error, control_ok, ControlCtx};
use crate::meta::ErrorCode;

/// The overall wall-clock budget for one ladder run.
///
/// Sized so every rung of the six-rung ladder gets attempted at the node's real per-tier timeout
/// (5s), with headroom — the point of the diagnostic is to reproduce what the ladder actually does,
/// so cutting it short would report "skipped" for tiers that would have been tried in a real dial.
/// It is still a hard bound: #1985 requires that a black-holed address cannot hang the caller, so a
/// rung that overruns costs the tail of the ladder a `skipped` row rather than an open-ended wait.
pub const PING_OVERALL_DEADLINE: Duration = Duration::from_secs(45);

/// Handle `control.peers.ping`.
///
/// Params: `{ peer: string, peer_id?: string }`.
/// * `peer` — a 64-hex `peer_id`, or a dialable `host:port` (IPv6 bracketed).
/// * `peer_id` — pins the identity the presented certificate MUST derive. It always wins over what
///   this node believes is at that address, which is what makes the wrong-identity case testable.
///
/// Result: the ladder report (see `ping::report_json`) — one row per rung plus a graded verdict.
/// A target that could not be resolved is a RESULT with `verdict: "unresolved"`, not an error: the
/// caller asked a diagnostic question and "I cannot tell what to dial, here is what is missing" is
/// a diagnostic answer.
pub async fn ping(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let peer = params.get("peer").and_then(Value::as_str).unwrap_or("");
    if peer.trim().is_empty() {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.peers.ping: params.peer is required (a 64-hex peer_id or a host:port address)",
        );
    }
    let explicit_peer_id = params
        .get("peer_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Both come from the SAME running peer network. Without it there is nothing honest to report:
    // the node has no identity to present, no relay reservation for the relayed rung, and no
    // authenticated pool to name who lives at an address.
    let Some(ping_ctx) = ctx.node.peer_ping_context() else {
        return control_error(
            id,
            ErrorCode::ControlError,
            "no peer network is running on this node, so there is no connection ladder to test",
        );
    };
    let known = ctx
        .node
        .gossip_handle()
        .map(ping::known_peers)
        .unwrap_or_default();

    match ping::ping_peer(
        ping_ctx,
        peer,
        explicit_peer_id,
        &known,
        PING_OVERALL_DEADLINE,
    )
    .await
    {
        Ok(report) => control_ok(id, report),
        // A refusal is NOT a ladder result — nothing was dialed — so it must not be dressed up as
        // one. It carries the catalogued PEER_PING_REFUSED code and says which bound was hit.
        Err(refused) => control_error(
            id,
            ErrorCode::PeerPingRefused,
            format!("control.peers.ping refused: {}", refused.summary()),
        ),
    }
}

/// A one-line operator summary of a ping result, for the CLI's human output.
///
/// Leads with the SEVERITY marker so a relay-only result reads as the yellow finding it is rather
/// than blending into a wall of "connected". Falls back gracefully on a result shape it does not
/// recognise, so an older/newer node can never make the CLI print nothing.
pub fn format_report(result: &Value) -> String {
    let severity = result["severity"].as_str().unwrap_or("?");
    let marker = match severity {
        "ok" => "OK",
        "warn" => "WARN",
        _ => "FAIL",
    };
    let peer = result["peer"].as_str().unwrap_or("?");
    let summary = result["summary"].as_str().unwrap_or("(no summary)");
    let mut out = format!("[{marker}] ping {peer}: {summary}");
    for rung in result["ladder"].as_array().unwrap_or(&Vec::new()) {
        out.push_str(&format!("\n    {}", format_rung(rung)));
    }
    out
}

/// One ladder rung as an operator-readable line: the tier, what it did, and the detail that makes
/// the row actionable (the address family it landed on, or dig-nat's own failure text).
fn format_rung(rung: &Value) -> String {
    let tier = rung["tier"].as_str().unwrap_or("?");
    match rung["result"].as_str().unwrap_or("?") {
        "connected" => format!(
            "{tier:<11} connected  {} ({}) in {}ms",
            rung["remote_addr"].as_str().unwrap_or("?"),
            rung["family"].as_str().unwrap_or("?"),
            rung["elapsed_ms"].as_u64().unwrap_or(0),
        ),
        "failed" => format!(
            "{tier:<11} failed     {}",
            rung["reason"].as_str().unwrap_or("(no reason)")
        ),
        // The WRONG-PEER row. It reads as a failure to dig-nat (the mTLS pin refuses the handshake),
        // so it must be called out by name here or an impersonation renders as an ordinary dead rung.
        "identity-mismatch" => format!(
            "{tier:<11} WRONG PEER answered as {}",
            rung["observed_peer_id"]
                .as_str()
                .unwrap_or("an undisclosed identity"),
        ),
        // `unavailable` and `skipped` both mean "nothing was dialed", so neither claims a duration;
        // the reason carries whether the gap is this node's configuration or the run's deadline.
        other => format!(
            "{tier:<11} {other:<10} {}",
            rung["reason"].as_str().unwrap_or("")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// **Proves:** the summary line leads with a marker that matches the graded severity, so a
    /// relay-only result cannot be mistaken for a clean one at a glance.
    ///
    /// **Catches:** rendering every result identically — the exact collapse #1929 hid behind, where
    /// "connected" said nothing about whether the direct path had been available.
    #[test]
    fn the_summary_marker_tracks_the_graded_severity() {
        let ok = format_report(&json!({
            "peer": "p", "severity": "ok", "summary": "reachable over the direct tier",
            "ladder": [],
        }));
        assert!(ok.starts_with("[OK]"), "{ok}");

        let warn = format_report(&json!({
            "peer": "p", "severity": "warn", "summary": "only through the relay",
            "ladder": [],
        }));
        assert!(warn.starts_with("[WARN]"), "{warn}");

        let err = format_report(&json!({
            "peer": "p", "severity": "error", "summary": "WRONG PEER",
            "ladder": [],
        }));
        assert!(err.starts_with("[FAIL]"), "{err}");
    }

    /// **Proves:** every rung is rendered, including the ones that failed or were skipped — the
    /// LADDER is the answer, not just the winner.
    ///
    /// **Catches:** a renderer that prints only the successful tier, which would hide "direct
    /// failed, relayed succeeded" — the actionable half of the report.
    #[test]
    fn every_rung_is_rendered_not_just_the_winner() {
        let out = format_report(&json!({
            "peer": "p", "severity": "warn", "summary": "relay only",
            "ladder": [
                {"tier": "direct", "result": "failed", "reason": "no route to host", "elapsed_ms": 5000},
                {"tier": "hole-punch", "result": "skipped", "reason": "deadline"},
                {"tier": "relayed", "result": "connected", "remote_addr": "[2001:db8::1]:9444",
                 "family": "ipv6", "observed_peer_id": "aa", "elapsed_ms": 120},
            ],
        }));
        assert!(out.contains("direct"), "{out}");
        assert!(out.contains("no route to host"), "{out}");
        assert!(out.contains("hole-punch"), "{out}");
        assert!(out.contains("relayed"), "{out}");
        assert!(
            out.contains("ipv6"),
            "the winning address family is visible: {out}"
        );
    }

    /// **Proves:** the WRONG-PEER rung is called out by name and names who answered.
    ///
    /// **Catches:** rendering it through the generic fallback arm, which would print
    /// `direct  identity-mismatch` with the answering id nowhere in sight — the one fact an operator
    /// needs when a peer is being impersonated or an address-book entry has gone stale.
    #[test]
    fn a_wrong_peer_rung_is_called_out_by_name() {
        let out = format_report(&json!({
            "peer": "p", "severity": "error", "summary": "WRONG PEER: ...",
            "ladder": [
                {"tier": "direct", "result": "identity-mismatch",
                 "observed_peer_id": "beef", "reason": "peer_id mismatch", "elapsed_ms": 9},
            ],
        }));
        assert!(out.contains("WRONG PEER"), "{out}");
        assert!(
            out.contains("beef"),
            "the answering identity is visible: {out}"
        );
    }

    /// **Proves:** an unfamiliar result shape still prints something readable.
    ///
    /// **Catches:** an index-panic or a silently empty line when a field is missing — the CLI must
    /// degrade honestly against an older or newer node rather than crash or say nothing.
    #[test]
    fn an_unrecognised_result_still_renders() {
        let out = format_report(&json!({}));
        assert!(out.contains("ping ?"), "{out}");
        assert!(out.contains("no summary"), "{out}");
    }
}
