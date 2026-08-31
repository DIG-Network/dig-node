//! `dign network-info` — this node's own network posture (dig-node#303).
//!
//! The node has always ANSWERED this question: `dig.getNetworkInfo` is served over the loopback
//! JSON-RPC surface and returns the node's `peer_id`, network id, effective L2 genesis, advertised
//! candidate addresses (IPv6-first, §5.2), reachability and relay reservation. What did not exist
//! was a way to ASK it from the command line — `dig-node network-info` was reported as producing
//! empty output on three healthy fleet boxes, which is what an unrecognised subcommand looks like
//! once a shell has swallowed the usage text. `peers` on the same boxes in the same session
//! answered, so the data was there and only the verb was missing.
//!
//! # Why this reads the OPEN surface rather than a `control.*` method
//!
//! Everything here is already published to strangers: the same `dig.getNetworkInfo` body is what
//! this node hands any peer that dials it, so a loopback caller learns nothing a peer does not.
//! Reading it through the token-gated control plane would therefore buy no confidentiality while
//! costing real availability — on a `.deb` install the control token is `0600 root:root`
//! (#501), so an ordinary user asking "what is my node's address" would be told to elevate for a
//! read the network performs for free. It is served token-free for that reason, deliberately, and
//! that is a property to preserve rather than an oversight to tighten later.

use serde_json::{json, Value};

use crate::cli::Outcome;
use crate::config::Config;
use crate::control_client::call_open;

/// Run `network-info`: read `dig.getNetworkInfo` from the running node and render it.
pub fn run(config: &Config) -> std::io::Result<Outcome> {
    let result = call_open(config, "dig.getNetworkInfo", json!({}))?;
    Ok(Outcome::new(format_network_info(&result), result))
}

/// Render the node's network posture as an operator-friendly block. PURE over the RPC result.
///
/// Every field is rendered from what the node actually returned: an absent field prints as
/// `unknown` rather than as a plausible default, because a fabricated `direct` or an invented
/// `0.0.0.0` reads exactly like a measurement and would be acted on as one.
fn format_network_info(result: &Value) -> String {
    let text = |key: &str| {
        result[key]
            .as_str()
            .map_or_else(|| "unknown".to_string(), str::to_string)
    };

    let mut out = format!(
        "dig-node network info:\n  peer id      {}\n  network      {}\n  genesis      {}",
        text("peer_id"),
        text("network_id"),
        text("genesis"),
    );
    out.push_str(&format!("\n  listen addr  {}", text("listen_addr")));
    out.push_str(&format!("\n  reachability {}", text("reachability")));

    // The advertised candidates in the order the node advertises them, which is IPv6-first (§5.2).
    // Reordering here would hide a node whose IPv6 advertisement is missing — the exact fault an
    // operator runs this command to find — so the order is passed through untouched.
    let candidates: Vec<&str> = result["candidate_addresses"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if candidates.is_empty() {
        out.push_str("\n  candidates   none advertised (this node is not dialable by peers)");
    } else {
        out.push_str("\n  candidates:");
        for addr in candidates {
            out.push_str(&format!("\n    • {addr}"));
        }
    }

    if let Some(url) = result["relay"]["url"].as_str() {
        let reserved = result["relay"]["reserved"].as_bool().unwrap_or(false);
        out.push_str(&format!(
            "\n  relay        {url} — reservation {}",
            if reserved { "held" } else { "none" }
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole posture renders, and the candidate order the node chose survives verbatim.
    #[test]
    fn renders_posture_and_preserves_the_advertised_candidate_order() {
        let s = format_network_info(&json!({
            "peer_id": "aa11",
            "network_id": "mainnet",
            "genesis": "ccd5bb71183532bff220ba46c268991a00000000000000000000000000000000",
            "listen_addr": "[2001:db8::5]:9444",
            "reachability": "relayed",
            "candidate_addresses": ["[2001:db8::5]:9444", "203.0.113.7:9444"],
            "relay": { "url": "wss://relay.dig.net:443", "reserved": true },
        }));
        assert!(s.contains("aa11"));
        assert!(s.contains("mainnet"));
        assert!(s.contains("relayed"));
        assert!(s.contains("relay.dig.net"));
        assert!(s.contains("reservation held"));
        // Two candidates, IPv6 first — asserted by POSITION, so a re-sort is visible here. A
        // `contains` on each address alone would pass under any ordering, including one that
        // demoted the IPv6 candidate the §5.2 policy exists to keep first.
        let v6 = s.find("[2001:db8::5]:9444").unwrap();
        let v4 = s.find("203.0.113.7:9444").unwrap();
        assert!(v6 < v4, "advertised order must pass through untouched: {s}");
    }

    /// A node advertising nothing says so. The tempting alternative — printing the listen address
    /// as though it were a candidate — would report a dialable endpoint that no peer was ever
    /// offered, which is the failure this verb exists to expose.
    #[test]
    fn no_candidates_is_stated_not_silently_omitted() {
        let s = format_network_info(&json!({
            "peer_id": "bb22",
            "candidate_addresses": [],
        }));
        assert!(s.contains("none advertised"), "{s}");
        assert!(s.contains("not dialable"), "{s}");
    }

    /// A field the node did not send prints as `unknown`. Nobody observed a reachability here, and
    /// `direct` — the value a plain `unwrap_or_default` on a string would never produce, but which
    /// a hand-written default reaches for — would be a claim about the network drawn from nothing.
    #[test]
    fn an_absent_field_prints_unknown_rather_than_a_plausible_default() {
        let s = format_network_info(&json!({ "peer_id": "cc33" }));
        assert!(s.contains("unknown"), "{s}");
        assert!(!s.contains("direct"), "a missing reachability must not read as direct: {s}");
    }
}
