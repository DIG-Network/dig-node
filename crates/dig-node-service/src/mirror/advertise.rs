//! Where this node tells the network its stores can be fetched from (dig-node#426).
//!
//! A mirror coin publishes URLs in its memos, and `dig_mirror_coin::create` refuses an
//! advertisement carrying none — so until this node can name a place a stranger can reach it, it
//! cannot bond anything. This module is that name, and nothing more: it turns one operator-set
//! string into the URL list the advertisement takes.
//!
//! # Why the value is CONFIGURED and never derived
//!
//! The one address this machine can derive on its own is the STUN reflexive address the peer seam
//! discovers, and it is the wrong thing to publish. A mirror coin's URLs are **fixed at create** for
//! the whole epoch, so an address that is unreachable from outside — symmetric NAT, no forwarded
//! port — or that simply changes leaves real $DIG staked on a claim the node cannot keep, which
//! SPEC.md §25 penalises. [`crate::config::is_self_upstream`] records the same limit for the
//! upstream slot: a node cannot decide its own public name by resolver alone.
//!
//! So an unset value is not a failure state. It means this node advertises nothing, creates no
//! mirror coin, and says so — which is strictly better than publishing somewhere nobody can fetch
//! from.
//!
//! # Changing it later costs money
//!
//! A coin's URLs cannot be edited. Correcting this list only affects coins created after the change;
//! bringing existing coins into line means reclaiming and re-creating them, a round trip and a fee.
//! Nothing here reclaims on a config change — spending money in response to a text edit is not a
//! behaviour an operator asked for.

use std::net::Ipv4Addr;

/// The operator-set list of URLs this node advertises. Entries are separated by commas or
/// whitespace, so both `a,b` and a shell-quoted `"a b"` work.
///
/// IPv6 entries SHOULD be listed first (CLAUDE.md §5.2), but the order is the operator's and this
/// module publishes it verbatim.
pub const ADVERTISE_URLS_ENV: &str = "DIG_MIRROR_ADVERTISE_URLS";

/// Why one entry was not advertised.
///
/// Named rather than folded into a bare skip so the warning can say which mistake was made — the
/// two are produced by very different operator errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Not an absolute URL with a scheme and a host. A bare `example.com` lands here: a memo entry
    /// with no scheme tells a fetcher nothing about how to reach it.
    NotAbsolute,
    /// A host that can only ever mean *this machine* — loopback, the unspecified address,
    /// link-local, `localhost`, or the `dig.local` alias. Publishing one advertises an address every
    /// reader resolves to themselves, which is the exact mistake of copying the node's own local
    /// address into the slot.
    ThisMachineOnly,
}

impl Rejection {
    /// Every variant, so the operator-message guard can walk the set rather than a chosen example.
    ///
    /// Declared beside the enum, not spelled inside the test. A walk built from an array literal in
    /// the test would still compile, still be the same length, and still pass after a variant was
    /// added — so the new variant's message would ship unguarded by the very test written to guard
    /// it, which is the shape of gap this module already shipped once.
    ///
    /// **What is and is not enforced, stated precisely because the looser claim was wrong.** The
    /// `match` in [`rejection_reason`] is exhaustive, so a new variant CANNOT compile without a
    /// developer editing this module and giving it a message. Nothing in Rust then forces that
    /// variant into this array — but the guard asserts its walk against `ALL.len()`, so the walk and
    /// this list cannot drift apart, and this is the one place to add it.
    pub const ALL: [Rejection; 2] = [Rejection::NotAbsolute, Rejection::ThisMachineOnly];
}

/// What [`parse_advertised_urls`] made of the operator's value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Advertised {
    /// The URLs to publish, in the operator's own order, duplicates removed.
    ///
    /// Deliberately NOT reordered. §5.2 prefers IPv6 first and this module's documentation says so,
    /// but these entries are advisory fetch hints belonging to the operator; silently sorting them
    /// would misstate a preference this node does not hold.
    pub accepted: Vec<String>,
    /// Entries that will not be published, each with the reason, for the operator-facing warning.
    pub rejected: Vec<(String, Rejection)>,
}

impl Advertised {
    /// Whether this node can advertise at all. `false` is the honest default, not an error.
    pub fn can_advertise(&self) -> bool {
        !self.accepted.is_empty()
    }
}

/// Reads the operator's advertised-URL list from the environment.
pub fn advertised_urls_from_env() -> Advertised {
    parse_advertised_urls(&std::env::var(ADVERTISE_URLS_ENV).unwrap_or_default())
}

/// Why one configured entry is not advertised, in the words an operator reads.
///
/// Split out of [`configured_urls`] so a test can walk EVERY variant and assert over the rendered
/// text. That is not tidiness: all three of this module's operator-facing lines shipped with 14- to
/// 18-space runs baked into the middle of a sentence, left behind when a `\` string continuation
/// lost its backslash. Such a literal compiles, no caller inspects it, and the mangled and correct
/// forms are indistinguishable in a diff — so only a test over the VALUE can see it, and it has to
/// reach these literals rather than a neighbouring module's.
fn rejection_reason(why: &Rejection) -> &'static str {
    match why {
        Rejection::NotAbsolute => {
            "it is not an absolute URL with a scheme and a host, so it names no way to reach anything"
        }
        Rejection::ThisMachineOnly => {
            "its host can only mean this machine, so every reader would resolve it to themselves"
        }
    }
}

/// The whole line an operator sees when one entry is dropped, the reason included.
///
/// The wrapper around the reason is operator-facing prose too, so it belongs in the guard's walk.
/// Checking only the reason would leave the sentence it is embedded in unchecked while the guard
/// claims to cover every line this module emits.
fn not_advertised(reason: &str) -> String {
    format!("{ADVERTISE_URLS_ENV} entry is not advertised: {reason}")
}

/// What this node reports when at least one entry survived and will be published.
const ADVERTISING_AT_CONFIGURED_URLS: &str =
    "advertising this node's stores at the operator-configured URLs, in the configured order";

/// What this node reports when no configured entry may be published.
///
/// A function rather than a `const` because it names the environment variable, and `concat!` cannot
/// take a `const`. Spelling the variable a second time as a literal would be a second source of
/// truth for the same name — exactly the drift this module's tests exist to catch.
fn nothing_publishable() -> String {
    format!(
        "no {ADVERTISE_URLS_ENV} entry is publishable, so this node advertises nothing and creates no mirror coin (SPEC.md 25.10)"
    )
}

/// The URLs this node will publish, with every rejected entry reported to the operator.
///
/// This is the whole operator surface as the mirror scheduler consumes it: one call, at bring-up,
/// yielding the list `create` advertises. An empty answer is the honest default rather than an
/// error — `NodeMirrorEffects::create` refuses by name on it, before any chain read, so a node with
/// nothing to advertise stakes nothing.
///
/// The warnings are emitted HERE rather than at the call site because this is the only place that
/// knows WHY an entry was dropped; a caller handed a shortened list could only report that some
/// entry was missing, which is not something an operator can act on.
pub fn configured_urls() -> Vec<String> {
    let advertised = advertised_urls_from_env();

    for (entry, why) in &advertised.rejected {
        tracing::warn!(
            target: "mirror",
            entry = %entry,
            "{}",
            not_advertised(rejection_reason(why))
        );
    }

    if advertised.can_advertise() {
        tracing::info!(
            target: "mirror",
            urls = ?advertised.accepted,
            "{ADVERTISING_AT_CONFIGURED_URLS}"
        );
    } else {
        tracing::info!(target: "mirror", "{}", nothing_publishable());
    }

    advertised.accepted
}

/// Turns one operator-set string into the advertisement's URL list.
///
/// # What is deliberately NOT rejected
///
/// **Any scheme is accepted.** `dig-mirror-coin` imposes no scheme rule — its reader treats URLs as
/// advisory and its SPEC constrains only that at least one exists — so refusing anything but
/// `http(s)` would be a stricter rule than anything shipped, and would pre-emptively break a
/// `dig://` form the ecosystem may well want.
///
/// **A private or LAN address is accepted.** An operator running a LAN-only deployment has made a
/// real choice, and refusing it would stop them bonding at all; accepting it risks only their own
/// stake. Rejection is reserved for hosts that cannot mean anywhere but this machine, where there is
/// no legitimate reading at all.
pub fn parse_advertised_urls(raw: &str) -> Advertised {
    let mut out = Advertised::default();

    for entry in raw.split([',', ' ', '\t', '\n', '\r']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        match classify(entry) {
            Some(reason) => out.rejected.push((entry.to_string(), reason)),
            None => {
                if !out.accepted.iter().any(|url| url == entry) {
                    out.accepted.push(entry.to_string());
                }
            }
        }
    }

    out
}

/// `None` when the entry is publishable; otherwise why it is not.
fn classify(entry: &str) -> Option<Rejection> {
    let Ok(parsed) = url::Url::parse(entry) else {
        return Some(Rejection::NotAbsolute);
    };
    let Some(host) = parsed.host() else {
        return Some(Rejection::NotAbsolute);
    };

    let this_machine_only = match host {
        url::Host::Domain(name) => match name.parse::<Ipv4Addr>() {
            // A NON-SPECIAL scheme — `dig://`, which this module accepts on purpose — takes the
            // WHATWG *opaque-host* path, so its host is never IP-parsed and a bare IPv4 literal
            // arrives here as a domain. Reading it back is what stops `dig://127.0.0.1/` reaching a
            // coin; without it the entire rule below is unreachable for every non-special scheme.
            Ok(ip) => is_this_machine_only_v4(ip),
            Err(_) => {
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                name == "localhost"
                    || name.ends_with(".localhost")
                    || name == crate::config::DIG_LOCAL_HOST
            }
        },
        url::Host::Ipv4(ip) => is_this_machine_only_v4(ip),
        url::Host::Ipv6(ip) => {
            // `is_unicast_link_local` is unstable, so the `fe80::/10` prefix is tested directly.
            //
            // The v6 predicates are asked FIRST and the embedded-v4 rule only after, which is
            // load-bearing rather than stylistic: `::1` unwraps to `0.0.0.1`, an ordinary global
            // v4 address, so asking the v4 rule first would ACCEPT the IPv6 loopback.
            ip.is_loopback()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                // `to_ipv4` rather than `to_ipv4_mapped`: it covers the deprecated IPv4-COMPATIBLE
                // form (`::127.0.0.1`) as well as the mapped one, and both are written by hand as
                // readily as the plain literal. A compatible address means exactly its embedded v4,
                // so there is no case where the wider unwrap answers a question the narrower one
                // should have declined.
                || ip.to_ipv4().is_some_and(is_this_machine_only_v4)
        }
    };

    this_machine_only.then_some(Rejection::ThisMachineOnly)
}

/// Whether an IPv4 address can only ever mean the machine reading it.
///
/// The single home of the v4 half of §25.10's rule. Three different paths can produce a v4 address —
/// the `Ipv4` host arm, a non-special scheme's opaque host, and an IPv4-mapped or -compatible IPv6
/// address — and each of them funnels through here, so no two of them can drift into disagreeing
/// about what "this machine" means.
///
/// Alternate IPv4 spellings (decimal, hex, octal, short form) need no handling: `url` normalises
/// them before `classify` ever sees the host.
fn is_this_machine_only_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every operator-facing line this module emits reads as a sentence.**
    ///
    /// All three of them shipped corrupted: a `\` string continuation lost its backslash and baked
    /// 14 to 18 literal spaces into the middle of each sentence. Nothing else can catch that. The
    /// compiler is happy, no caller inspects the text, the two forms are indistinguishable in a
    /// diff, and the only witness is an operator reading a line that looks broken at the moment
    /// they are trying to work out why nothing is being advertised.
    ///
    /// The guard walks the whole SET rather than a chosen example, and asserts the count, so
    /// deleting a message from the walk fails here instead of silently shrinking the sweep. A
    /// sibling guard over `lifecycle.rs`'s two refusals exists and is NOT a substitute: it cannot
    /// reach these literals, which is how three corrupted runtime lines sat behind a green test
    /// that appeared to cover them.
    #[test]
    fn every_operator_facing_line_reads_as_a_sentence() {
        // Driven from `Rejection::ALL`, and the expected count is DERIVED from it rather than
        // written as a literal. A hard-coded `4` would actively cement a subset: add a variant,
        // give it a message, leave it out of `ALL`, and a literal count still matches while the new
        // line ships unchecked. The `match` below only forces the variant to be NAMED — that is
        // what makes it visible, not what makes it walked — so the derived length is what actually
        // ties the two together.
        let lines: Vec<(&str, String)> = Rejection::ALL
            .iter()
            .map(|why| {
                let name = match why {
                    Rejection::NotAbsolute => "Rejection::NotAbsolute",
                    Rejection::ThisMachineOnly => "Rejection::ThisMachineOnly",
                };
                // The wrapper, not the bare reason: that is the line an operator actually reads,
                // and it contains the reason, so this covers both.
                (name, not_advertised(rejection_reason(why)))
            })
            .chain([
                (
                    "ADVERTISING_AT_CONFIGURED_URLS",
                    ADVERTISING_AT_CONFIGURED_URLS.to_string(),
                ),
                ("nothing_publishable", nothing_publishable()),
            ])
            .collect();

        assert_eq!(
            lines.len(),
            Rejection::ALL.len() + 2,
            "every line this module emits must be walked, never a subset: {lines:?}"
        );
        for (name, line) in &lines {
            assert!(
                !line.contains("  "),
                "{name}: a run of two spaces is an eaten line continuation, not prose: {line:?}"
            );
            assert!(
                !line.chars().any(char::is_control),
                "{name}: no control character belongs in an operator-facing line: {line:?}"
            );
            // Control: a fixture too empty to exhibit the property must not pass. Both assertions
            // above are satisfied by "" and by a single word.
            assert!(
                line.split_whitespace().count() >= 8,
                "{name}: control -- each line must still be a sentence saying what happened: {line:?}"
            );
        }
        assert!(
            lines[3].1.contains(ADVERTISE_URLS_ENV),
            "control: the no-entry line must name the variable an operator has to set: {:?}",
            lines[3].1
        );
    }

    /// The refusal that exists today survives an unset value: no URL means no advertisement, which
    /// is what makes `create` decline rather than publish somewhere unreachable.
    #[test]
    fn an_unset_value_advertises_nothing() {
        for raw in ["", "   ", ",, ,"] {
            let got = parse_advertised_urls(raw);
            assert!(!got.can_advertise(), "{raw:?} must not advertise");
            assert!(got.accepted.is_empty(), "{raw:?}");
        }
    }

    /// A this-machine entry is dropped while a genuinely public sibling in the SAME list survives.
    ///
    /// The two-kind fixture is the point: a test asserting only that the result is empty would be
    /// satisfied identically by a blanket refusal of every entry, and could not tell a targeted
    /// rejection from one that throws the good URL away with the bad one.
    #[test]
    fn a_this_machine_host_is_dropped_and_its_public_sibling_survives() {
        let got = parse_advertised_urls(
            "http://127.0.0.1:4161/, https://mirror.example.net/, http://localhost:4161/, \
             http://[::1]:4161/, http://dig.local/, http://169.254.10.4/",
        );

        assert_eq!(
            got.accepted,
            vec!["https://mirror.example.net/".to_string()]
        );
        assert_eq!(got.rejected.len(), 5, "{:?}", got.rejected);
        assert!(got
            .rejected
            .iter()
            .all(|(_, why)| *why == Rejection::ThisMachineOnly));
    }

    /// A LAN address is published, not refused — an operator on a private deployment has made a
    /// real choice and risks only their own stake.
    ///
    /// Paired with the case above, this is what separates "reject what can only mean this machine"
    /// from the nearest wrong implementation, "reject anything not globally routable".
    #[test]
    fn a_private_lan_address_is_accepted() {
        let got = parse_advertised_urls("http://10.0.0.5:4161/ http://192.168.1.9:4161/");
        assert_eq!(got.accepted.len(), 2, "{got:?}");
        assert!(got.rejected.is_empty(), "{:?}", got.rejected);
    }

    /// No scheme allowlist. `dig-mirror-coin` imposes none, so neither does this.
    #[test]
    fn any_scheme_is_accepted() {
        let got = parse_advertised_urls("dig://node.example/ https://node.example/");
        assert_eq!(got.accepted.len(), 2, "{got:?}");
    }

    /// A schemeless entry names no way to reach anything, so it is not published.
    #[test]
    fn a_schemeless_entry_is_refused() {
        let got = parse_advertised_urls("mirror.example.net");
        assert!(got.accepted.is_empty(), "{got:?}");
        assert_eq!(
            got.rejected,
            vec![("mirror.example.net".to_string(), Rejection::NotAbsolute)]
        );
    }

    /// The operator's order is published verbatim. Asserting BOTH orders is what proves no sort is
    /// applied: a single IPv6-first fixture is satisfied by an implementation that sorts IPv6 first.
    #[test]
    fn the_operators_order_is_preserved_in_both_directions() {
        let v6 = "https://[2001:db8::1]/".to_string();
        let v4 = "https://198.51.100.7/".to_string();

        assert_eq!(
            parse_advertised_urls(&format!("{v6} {v4}")).accepted,
            vec![v6.clone(), v4.clone()]
        );
        assert_eq!(
            parse_advertised_urls(&format!("{v4} {v6}")).accepted,
            vec![v4, v6]
        );
    }

    /// A bare IPv4 literal under a NON-SPECIAL scheme is still this machine.
    ///
    /// `dig://` is a tested, intended input (see `any_scheme_is_accepted`), and a non-special scheme
    /// takes the WHATWG **opaque-host** path: the value arrives as `Host::Domain("127.0.0.1")`, so
    /// the `Host::Ipv4` arm holding the loopback rule never runs. The scheme is named in the fixture
    /// because the defect lives in the scheme, not in the host.
    #[test]
    fn a_non_special_scheme_does_not_smuggle_a_this_machine_host_past_the_opaque_host_path() {
        let got = parse_advertised_urls("dig://127.0.0.1:4161/ dig://0.0.0.0/ dig://node.example/");

        assert_eq!(
            got.accepted,
            vec!["dig://node.example/".to_string()],
            "only the honest control may survive: {got:?}"
        );
        assert_eq!(got.rejected.len(), 2, "{:?}", got.rejected);
        assert!(got
            .rejected
            .iter()
            .all(|(_, why)| *why == Rejection::ThisMachineOnly));
    }

    /// An IPv6 address that merely WRAPS an IPv4 one means whatever the embedded address means.
    ///
    /// `Ipv6Addr::is_loopback` is true only of `::1`, and the meaning of a mapped or compatible form
    /// lives entirely in its low 32 bits — so a rule that reads only the v6 predicates sees
    /// `[::ffff:127.0.0.1]` as an ordinary global address. The honest sibling in the same list is
    /// what separates this from a blanket refusal of every bracketed host.
    #[test]
    fn an_ipv4_wrapped_in_ipv6_is_judged_by_the_address_it_embeds() {
        let got = parse_advertised_urls(
            "http://[::ffff:127.0.0.1]/, http://[::127.0.0.1]/, http://[::ffff:0.0.0.0]/, \
             http://[::ffff:169.254.10.4]/, http://[2001:db8::1]/",
        );

        assert_eq!(
            got.accepted,
            vec!["http://[2001:db8::1]/".to_string()],
            "only the genuinely global entry may survive: {got:?}"
        );
        assert_eq!(got.rejected.len(), 4, "{:?}", got.rejected);
        assert!(got
            .rejected
            .iter()
            .all(|(_, why)| *why == Rejection::ThisMachineOnly));
    }

    /// The widening does not overshoot. A LAN address stays publishable however it is written, and
    /// `::1` keeps its own meaning rather than being read through its low 32 bits as `0.0.0.1`.
    ///
    /// Both halves are controls the widening could plausibly break: unwrapping an embedded v4
    /// unconditionally would turn `[::1]` into an accepted host, and applying the v4 rule to a
    /// mapped LAN address would refuse a choice the operator is allowed to make.
    #[test]
    fn the_this_machine_rule_still_permits_a_lan_address_and_still_refuses_bare_ipv6_loopback() {
        let permitted = parse_advertised_urls("http://192.168.1.10/ http://[::ffff:192.168.1.10]/");
        assert_eq!(permitted.accepted.len(), 2, "{permitted:?}");
        assert!(permitted.rejected.is_empty(), "{:?}", permitted.rejected);

        let refused = parse_advertised_urls("http://[::1]/ http://[::]/");
        assert!(refused.accepted.is_empty(), "{refused:?}");
        assert_eq!(refused.rejected.len(), 2, "{:?}", refused.rejected);
    }

    /// The memo layout carries many URLs, so several entries is the designed case; an exact
    /// duplicate is published once, because two identical memo entries advertise nothing extra.
    #[test]
    fn an_exact_duplicate_is_published_once() {
        let got =
            parse_advertised_urls("https://a.example/, https://a.example/, https://b.example/");
        assert_eq!(
            got.accepted,
            vec![
                "https://a.example/".to_string(),
                "https://b.example/".to_string()
            ]
        );
    }
}
