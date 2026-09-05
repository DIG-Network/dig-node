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

    // Every reflexive-address READING this node has gathered, plus the ESTABLISH verdict each
    // family reaches over them (dig-node#566). An operator debugging "why is my node
    // uncorroborated" needs to see which sources answered and what each said, not only the final
    // bond-state label `dign mirror bond-states` reports — that label says the address was refused;
    // this is where the operator learns WHY (one source, a dissenting source, too few independent
    // classes, or a private/CGNAT reading).
    out.push_str(&format_reflexive_readings(result));
    out
}

/// Render the `reflexive_addr` readings and the [`dig_stun::establish`] verdict each address family
/// reaches over them. PURE over the RPC result, reusing
/// [`crate::mirror::advertise::PublicAddress::from_network_info`]/`established` rather than
/// re-parsing the wire shape or re-deriving agreement here.
fn format_reflexive_readings(result: &Value) -> String {
    let address = crate::mirror::advertise::PublicAddress::from_network_info(result);
    if address.reflexive.is_empty() {
        return "\n  reflexive    none (no STUN tier has ever answered)".to_string();
    }

    let mut out = String::from("\n  reflexive readings:");
    for reading in &address.reflexive {
        out.push_str(&format!("\n    • {} -> {}", reading.source, reading.addr));
    }
    let established = address.established();
    out.push_str(&format!(
        "\n  reflexive verdict:\n    ipv6  {}\n    ipv4  {}",
        describe_family_verdict(&established.ipv6),
        describe_family_verdict(&established.ipv4),
    ));
    out
}

/// One [`dig_stun::establish::FamilyVerdict`], in a sentence an operator can act on without reading
/// `dig-stun`'s source — each variant names both what happened and, where there is one, the remedy.
fn describe_family_verdict(verdict: &dig_stun::establish::FamilyVerdict) -> String {
    use dig_stun::establish::FamilyVerdict;
    match verdict {
        FamilyVerdict::NoReadings => "no reading in this family".to_string(),
        FamilyVerdict::Disagreement { addrs } => format!(
            "DISAGREEMENT among {} reported addresses ({}) — a dissenting source blocks \
             establishment regardless of how many others agree",
            addrs.len(),
            addrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        FamilyVerdict::Insufficient { classes, peer_only } => format!(
            "agreed, but only {classes} independent source class(es) reported it (needs {} \
             {})",
            if *peer_only {
                dig_stun::establish::PEER_ONLY_MIN_CLASSES
            } else {
                dig_stun::establish::MIN_INDEPENDENT_CLASSES
            },
            if *peer_only {
                "since every agreeing class is a peer"
            } else {
                "independent classes"
            }
        ),
        FamilyVerdict::NotGlobal { ip, scope } => {
            format!("{ip} agreed, but is not globally routable ({scope:?})")
        }
        FamilyVerdict::Established { ip, classes } => {
            format!("ESTABLISHED at {ip} ({classes} independent classes agree)")
        }
    }
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
        assert!(
            !s.contains("direct"),
            "a missing reachability must not read as direct: {s}"
        );
    }

    /// No STUN tier has ever answered — the CLI says so plainly rather than printing an empty
    /// readings block, which would read as "gathered zero readings and moved on" rather than "never
    /// asked at all".
    #[test]
    fn no_reflexive_reading_is_stated_plainly() {
        let s = format_network_info(&json!({ "peer_id": "dd44" }));
        assert!(s.contains("no STUN tier has ever answered"), "{s}");
    }

    /// **The property: an operator sees WHY a family did not establish, not merely THAT it did
    /// not.** One source alone must print as `Insufficient` (naming the floor), never merely
    /// "not established" — that is the exact debugging information dig-node#566 exists to surface.
    #[test]
    fn one_source_prints_as_insufficient_not_merely_unestablished() {
        let s = format_network_info(&json!({
            "peer_id": "ee55",
            "reflexive_addr": [
                { "source": "relay:relay.example", "addr": "203.0.113.7:9444" },
            ],
        }));
        assert!(s.contains("relay:relay.example -> 203.0.113.7:9444"), "{s}");
        assert!(
            s.contains("only 1 independent source class(es)"),
            "must name the count and the floor, not just fail silently: {s}"
        );
    }

    /// **The distinguishing property: a DISSENTING third reading renders as DISAGREEMENT, never as
    /// a quiet pass for the majority.** Two classes agree on one address, a third reports a
    /// different one — the majority must NOT be reported as established, and the operator must see
    /// BOTH addresses named as the source of the conflict.
    #[test]
    fn a_dissenting_reading_renders_as_disagreement_naming_both_addresses() {
        let s = format_network_info(&json!({
            "peer_id": "ff66",
            "reflexive_addr": [
                { "source": "relay:relay.example", "addr": "203.0.113.7:9444" },
                { "source": "operator:198.51.100.1:19305", "addr": "203.0.113.7:9444" },
                { "source": "public:stun.example", "addr": "203.0.113.9:9444" },
            ],
        }));
        assert!(s.contains("DISAGREEMENT"), "{s}");
        assert!(
            s.contains("203.0.113.7") && s.contains("203.0.113.9"),
            "{s}"
        );
    }

    /// Two independent classes agreeing on a global-unicast address renders as ESTABLISHED, naming
    /// the address and the class count — the positive case, so the verdict line is never read as
    /// permanently bad news.
    #[test]
    fn two_agreeing_classes_render_as_established() {
        // Genuinely global-unicast, unlike the other two fixtures above: THIS is the one path that
        // reaches `dig_stun::establish`'s routability check (unanimity and class-count are checked
        // first and are satisfied here), so a documentation-range address would be refused as
        // `NotGlobal` instead of rendering ESTABLISHED — testing the wrong branch entirely.
        let s = format_network_info(&json!({
            "peer_id": "aa77",
            "reflexive_addr": [
                { "source": "relay:relay.example", "addr": "93.184.216.34:9444" },
                { "source": "public:stun.example", "addr": "93.184.216.34:9444" },
            ],
        }));
        assert!(s.contains("ESTABLISHED at 93.184.216.34"), "{s}");
        assert!(s.contains("2 independent classes agree"), "{s}");
    }
}
