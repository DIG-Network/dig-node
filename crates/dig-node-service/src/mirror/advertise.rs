//! Where this node tells the network its stores can be fetched from (dig-node#426).
//!
//! A mirror coin publishes URLs in its memos, and `dig_mirror_coin::create` refuses an
//! advertisement carrying none — so until this node can name a place a stranger can reach it, it
//! cannot bond anything. This module is that name: it decides the URL list the advertisement takes,
//! from the operator's own value when there is one and from this node's own public address when
//! there is not.
//!
//! # The value is DERIVED by default, and the operator's value overrides it
//!
//! The one address this machine can learn about itself is the reflexive address the peer seam
//! discovers — the NAT mapping of the dig-peer socket a stranger actually dials. A mirror coin's
//! URLs are **fixed at create** for the whole epoch, so that mapping may lapse before the epoch
//! does. Publishing it anyway is nonetheless the right default, because of what a wrong address
//! actually costs (below): the same as advertising nothing.
//!
//! So the node derives and publishes it, gated on LIVENESS rather than on a reachability proof —
//! [`PublicAddress::is_live`], a held relay reservation or a confirmed direct mapping. There is no
//! probe-back and no confirm-before-stake step: enforcement is economic, not predictive.
//!
//! # What an unreachable advertisement actually costs — forfeiture, never principal
//!
//! State this precisely, because the looser reading ("SPEC.md §25 penalises it") made this module
//! refuse to derive anything at all. §25 says *penalised* and never defines a mechanism; the
//! mechanism lives in `dig-mirror-coin`, and it has **no slash path**. Only the owner's key can
//! produce a reclaim spend (`dig-mirror-coin/SPEC.md` §5, §6.4), reclaim recreates the full locked
//! amount, and no path in that crate reduces $DIG supply (§3 rules 4 and 5). The only penalty any
//! code here applies is credit denial: [`super::bond_verify`] hands a coin that does not name the
//! serving peer a `BondVerdict::Unverified`, and an unverified bond earns nothing.
//!
//! So a bad URL costs **that epoch's rewards, capital locked until the operator reclaims it, and a
//! reclaim fee — never the principal**. Advertising nothing costs that same epoch's rewards. The
//! two failure directions are equal, which is why refusing to derive bought nothing.
//!
//! # Changing it later costs money
//!
//! A coin's URLs cannot be edited. Correcting this list only affects coins created after the change;
//! bringing existing coins into line means reclaiming and re-creating them, a round trip and a fee.
//! Nothing here reclaims on a config change — spending money in response to a text edit is not a
//! behaviour an operator asked for.

use std::net::{Ipv4Addr, SocketAddr};

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

/// The URL scheme a derived entry is published under.
///
/// Deliberately NOT `http`. `DIG_NODE_PORT` (9778) is the HTTP content port and it is
/// LOOPBACK-BOUND by default (see [`crate::config`]), so a relay cannot mediate it and a stranger
/// cannot reach it. What a stranger genuinely reaches is the dig-peer mTLS wire, which is the socket
/// the reflexive mapping is OF — so the derived URL names that transport rather than one this node
/// is not serving to the outside world. [`classify`] accepts a non-special scheme on purpose.
const DERIVED_SCHEME: &str = "dig";

/// What this node knows about where a stranger could reach it, as one pass reads it.
///
/// A plain value with no behaviour of its own beyond [`Self::is_live`], so the decision below is
/// pure over it and a test supplies a whole world in three fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicAddress {
    /// The reflexive addresses the peer seam has learned — the NAT mappings of THIS node's dig-peer
    /// socket, carrying their own ports.
    ///
    /// A list rather than one address because a dual-stack node can have a mapping per family.
    /// Ordering here is whatever the seam reported; [`derived_urls`] is what puts IPv6 first
    /// (CLAUDE.md §5.2).
    pub reflexive: Vec<SocketAddr>,
    /// Whether this node currently holds a relay reservation.
    pub relay_reserved: bool,
    /// Whether this node has a CONFIRMED direct inbound mapping (UPnP / NAT-PMP / PCP).
    ///
    /// **Nothing produces `true` today, and that is stated rather than left to be discovered.** The
    /// pool surfaces no mapping confirmation, so [`PublicAddress::from_network_info`] always reads
    /// this as `false` and the liveness gate rests on the relay reservation alone. The field exists
    /// because the decision is `reserved || direct mapping` and a gate that cannot express its
    /// second term is a gate that silently loses it; the tests drive this term directly, so the
    /// plumbing is correct the moment a producer exists.
    ///
    /// **What MUST NOT be wired to it:** `dig.getNetworkInfo`'s `reachability` field. That reports
    /// `"direct"` whenever no relay is in use, which is the ABSENCE of a relay rather than evidence
    /// of reachability — its own comment says so. Reading it here would make the gate vacuously
    /// true for every node that is not relayed, which is exactly the population the gate exists to
    /// stop advertising.
    pub direct_mapping: bool,
}

impl PublicAddress {
    /// Whether this node is reachable ENOUGH to stake an epoch on the address it knows.
    ///
    /// Liveness, not a reachability proof. §25.10's enforcement is economic: a node that cannot be
    /// reached simply earns nothing, so the gate asks only whether a path to this node is currently
    /// held rather than trying to predict whether one will hold for the epoch.
    pub fn is_live(&self) -> bool {
        self.relay_reserved || self.direct_mapping
    }

    /// Reads one pass's view out of `dig.getNetworkInfo`'s answer.
    ///
    /// The `reflexive_addr` key is accepted as EITHER one address string or an array of them, and
    /// anything that does not parse as a socket address is dropped. That tolerance is deliberate:
    /// the key is hard-coded `null` in `dig-node-core` today (`dig_ecosystem#3198` is adding the
    /// producer), so this adapter is written against a shape that does not exist yet. Every way of
    /// being wrong about it fails in the same direction — no derived address, so no create — which
    /// is the direction that costs an epoch's rewards rather than money.
    pub fn from_network_info(info: &serde_json::Value) -> Self {
        let reflexive = match &info["reflexive_addr"] {
            serde_json::Value::String(one) => one.parse::<SocketAddr>().into_iter().collect(),
            serde_json::Value::Array(many) => many
                .iter()
                .filter_map(|entry| entry.as_str()?.parse::<SocketAddr>().ok())
                .collect(),
            _ => Vec::new(),
        };
        Self {
            reflexive,
            relay_reserved: info["relay"]["reserved"].as_bool().unwrap_or(false),
            // Never read from `reachability` — see the field's own documentation.
            direct_mapping: false,
        }
    }
}

/// Which of §25.10's five outcomes this pass is in, and therefore what an operator is told.
///
/// Named states rather than a bare empty list because the four ways of publishing nothing have four
/// different remedies, and telling an operator the wrong one is the failure this taxonomy exists to
/// prevent: a node that cannot know its own address is not a node whose operator forgot to
/// configure something, and money will not clear it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertiseState {
    /// Publishing the operator's own list. Their value always wins.
    Override,
    /// Publishing this node's own reflexive peer address, because no operator value is set.
    Derived,
    /// The operator set a value and no entry in it is publishable.
    Off,
    /// No operator value, and this node does not know a public address it could publish.
    NoPublicAddress,
    /// A public address is known, but no path to this node is currently held.
    NoRelay,
}

impl AdvertiseState {
    /// Every variant, so the operator-message guard walks the SET rather than a chosen example.
    ///
    /// Declared beside the enum for the same reason [`Rejection::ALL`] is: a walk assembled inside
    /// the test would still compile and still pass after a variant was added, shipping the new
    /// state's line unguarded by the very test written to guard it.
    pub const ALL: [AdvertiseState; 5] = [
        AdvertiseState::Override,
        AdvertiseState::Derived,
        AdvertiseState::Off,
        AdvertiseState::NoPublicAddress,
        AdvertiseState::NoRelay,
    ];

    /// The machine-readable name, as §25.10's state taxonomy spells it.
    pub fn label(self) -> &'static str {
        match self {
            AdvertiseState::Override => "advertising_override",
            AdvertiseState::Derived => "advertising_derived",
            AdvertiseState::Off => "off",
            AdvertiseState::NoPublicAddress => "no_public_address",
            AdvertiseState::NoRelay => "no_relay",
        }
    }

    /// The sentence an operator reads for this state.
    ///
    /// A `String` rather than a `&'static str` because two of them name the environment variable,
    /// and spelling it a second time as a literal would be a second source of truth for the same
    /// name — the drift this module's tests exist to catch.
    pub fn reason(self) -> String {
        match self {
            AdvertiseState::Override => ADVERTISING_AT_CONFIGURED_URLS.to_string(),
            AdvertiseState::Derived => {
                "advertising this node's stores at its own public peer address, derived because no \
                 operator value is set"
                    .to_string()
            }
            AdvertiseState::Off => format!(
                "no {ADVERTISE_URLS_ENV} entry is publishable, so this node advertises nothing and \
                 creates no mirror coin (SPEC.md 25.10)"
            ),
            // Deliberately NOT phrased as something the operator has failed to configure. Setting
            // a value they cannot know is not a remedy, and a blocker no action of theirs can
            // clear must never be described as one.
            AdvertiseState::NoPublicAddress => {
                "this node does not know its public address yet, so it is not advertising mirrors \
                 and not earning; nothing has reported one"
                    .to_string()
            }
            AdvertiseState::NoRelay => {
                "this node knows its public address but holds neither a relay reservation nor a \
                 confirmed direct mapping, so it is not advertising mirrors and not earning until \
                 a path to it is held again"
                    .to_string()
            }
        }
    }
}

/// What this node will advertise this pass, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// The URLs `create` publishes. Empty in every state but [`AdvertiseState::Override`] and
    /// [`AdvertiseState::Derived`].
    pub urls: Vec<String>,
    /// Which outcome produced that list, for the refusal message and the operator surface.
    pub state: AdvertiseState,
}

impl Default for Effective {
    /// Nothing advertised, for the reason that is true before anything has been read.
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            state: AdvertiseState::NoPublicAddress,
        }
    }
}

impl Effective {
    /// Whether this node can advertise at all. `false` is an honest answer, not an error.
    pub fn can_advertise(&self) -> bool {
        !self.urls.is_empty()
    }
}

/// The URLs this node advertises this pass: the operator's value if there is one, otherwise its own
/// public address.
///
/// Pure over its two inputs, so a fixture is a parsed value and three fields.
///
/// # The order of the arms is the contract
///
/// 1. **An operator value that yields anything wins outright.** It is their statement of where their
///    own collateral is staked.
/// 2. **An operator value that yields NOTHING does not fall through to the derived address.** They
///    named a place; silently staking their money on a different one is a surprise about money, and
///    the warning naming their mistake is something they can act on. This also leaves the behaviour
///    of every already-configured node exactly as it shipped.
/// 3. **No known public address is reported BEFORE the liveness gate**, because it is the more
///    fundamental answer and it is the one true on a node whose relay is held but reports no
///    reflexive address — the state every host is in until `dig_ecosystem#3198` lands.
pub fn effective_urls(operator: &Advertised, address: &PublicAddress) -> Effective {
    if operator.can_advertise() {
        return Effective {
            urls: operator.accepted.clone(),
            state: AdvertiseState::Override,
        };
    }
    if !operator.rejected.is_empty() {
        return Effective {
            urls: Vec::new(),
            state: AdvertiseState::Off,
        };
    }

    let derived = derived_urls(address);
    if !derived.can_advertise() {
        return Effective {
            urls: Vec::new(),
            state: AdvertiseState::NoPublicAddress,
        };
    }
    if !address.is_live() {
        return Effective {
            urls: Vec::new(),
            state: AdvertiseState::NoRelay,
        };
    }
    Effective {
        urls: derived.accepted,
        state: AdvertiseState::Derived,
    }
}

/// This node's own reflexive addresses as publishable URLs, IPv6 first.
///
/// Every candidate goes through [`classify`], the same gate the operator's entries pass. A
/// reflexive address is a reading, not a promise: a seam that reports a loopback or link-local
/// mapping must not be able to put one into a coin merely because this node derived it rather than
/// an operator typing it.
fn derived_urls(address: &PublicAddress) -> Advertised {
    let (v6, v4): (Vec<&SocketAddr>, Vec<&SocketAddr>) =
        address.reflexive.iter().partition(|addr| addr.is_ipv6());

    let mut out = Advertised::default();
    for addr in v6.into_iter().chain(v4) {
        // `SocketAddr`'s own rendering already brackets an IPv6 host and carries the port, so this
        // is the one place the URL form is spelled and there is no second way to write it.
        let url = format!("{DERIVED_SCHEME}://{addr}");
        match classify(&url) {
            Some(reason) => out.rejected.push((url, reason)),
            None => {
                if !out.accepted.contains(&url) {
                    out.accepted.push(url);
                }
            }
        }
    }
    out
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

/// The operator's parsed value, with every rejected entry reported to them.
///
/// Read ONCE at bring-up: it is configuration rather than an observation, so re-reading it per pass
/// would buy nothing and would let the list a warning was emitted about drift from the list actually
/// published.
///
/// The warnings are emitted HERE rather than at the call site because this is the only place that
/// knows WHY an entry was dropped; a caller handed a shortened list could only report that some
/// entry was missing, which is not something an operator can act on.
///
/// It reports only the DROPPED entries and says nothing about what is being advertised. That
/// sentence is [`AdvertiseState::reason`]'s, because the answer now depends on this node's live
/// address and relay state and is therefore not knowable at bring-up.
pub fn configured_operator_urls() -> Advertised {
    let advertised = advertised_urls_from_env();

    for (entry, why) in &advertised.rejected {
        tracing::warn!(
            target: "mirror",
            entry = %entry,
            "{}",
            not_advertised(rejection_reason(why))
        );
    }

    advertised
}

/// One pass's advertisement decision, taking the operator's value from the environment.
///
/// The composition the scheduler performs, in one call, so a test can drive exactly it rather than
/// a re-assembled imitation of it.
pub fn effective_urls_from_env(address: &PublicAddress) -> Effective {
    effective_urls(&configured_operator_urls(), address)
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
            // Every state's sentence too, driven from its own `ALL` for the same reason. Five of
            // this module's operator-facing lines now live behind `AdvertiseState::reason`, and
            // `ADVERTISING_AT_CONFIGURED_URLS` is reached through the `Override` arm rather than
            // named separately, so no line is walked twice and none is missed.
            .chain(AdvertiseState::ALL.iter().map(|state| (state.label(), state.reason())))
            .collect();

        assert_eq!(
            lines.len(),
            Rejection::ALL.len() + AdvertiseState::ALL.len(),
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
        // Looked up BY NAME rather than by index. The walk gained five entries and an index into
        // it would have kept passing while pointing at a different sentence entirely.
        let off = AdvertiseState::Off.reason();
        assert!(
            off.contains(ADVERTISE_URLS_ENV),
            "control: the unpublishable-value line must name the variable an operator has to \
             correct: {off:?}"
        );
        // The converse control, and the one that matters more. An operator whose node cannot know
        // its own address CANNOT clear that by setting anything, so naming the variable there
        // would send them to a remedy that does not exist.
        let no_address = AdvertiseState::NoPublicAddress.reason();
        assert!(
            !no_address.contains(ADVERTISE_URLS_ENV),
            "a blocker no configuration can clear must not be described as configuration: \
             {no_address:?}"
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

    // -- The derived default (dig_ecosystem#3197) ------------------------------------------------

    /// A reflexive address, IPv4 first so the ordering assertion cannot pass by accident.
    fn reflexive(relay_reserved: bool) -> PublicAddress {
        PublicAddress {
            reflexive: vec![
                "198.51.100.7:9444".parse().expect("a v4 socket address"),
                "[2001:db8::1]:9444".parse().expect("a v6 socket address"),
            ],
            relay_reserved,
            direct_mapping: false,
        }
    }

    /// With an address known and a relay held, the node advertises its own peer socket — IPv6
    /// first, in `dig://` form.
    ///
    /// The scheme is asserted, not merely the presence of the address: `http://ip:9778` would name
    /// the HTTP content port, which is loopback-bound by default and which no relay mediates, so a
    /// coin carrying it would advertise somewhere no stranger can reach.
    ///
    /// The fixture lists IPv4 FIRST so that §5.2's IPv6-first ordering is proven rather than
    /// inherited from the input's own order.
    #[test]
    fn a_known_address_with_a_path_held_is_derived_and_advertised_ipv6_first() {
        let got = effective_urls(&Advertised::default(), &reflexive(true));

        assert_eq!(got.state, AdvertiseState::Derived, "{got:?}");
        assert_eq!(
            got.urls,
            vec![
                "dig://[2001:db8::1]:9444".to_string(),
                "dig://198.51.100.7:9444".to_string(),
            ],
            "the derived list must name the dig-peer wire, IPv6 first: {got:?}"
        );
        assert!(got.can_advertise());
    }

    /// No reflexive address means no advertisement — and the reason names the ADDRESS, never the
    /// operator's configuration.
    ///
    /// This is every host's state until `dig_ecosystem#3198` lands a producer, so the sentence it
    /// yields is the one an operator actually reads today. Telling them to configure something
    /// would send them to a remedy that cannot work.
    #[test]
    fn no_known_address_advertises_nothing_and_blames_the_address_not_the_operator() {
        let unknown = PublicAddress {
            relay_reserved: true,
            ..PublicAddress::default()
        };
        let got = effective_urls(&Advertised::default(), &unknown);

        assert_eq!(got.state, AdvertiseState::NoPublicAddress, "{got:?}");
        assert!(got.urls.is_empty(), "{got:?}");
        assert!(
            !got.state.reason().contains(ADVERTISE_URLS_ENV),
            "the reason must not send the operator to a setting that cannot clear it: {:?}",
            got.state.reason()
        );
    }

    /// A known address with NO path held advertises nothing, and says so as its own state.
    ///
    /// Distinct from the case above on purpose: the two have opposite remedies — one waits for an
    /// address, the other for a connection — and collapsing them into one empty list is what makes
    /// an operator chase the wrong thing.
    #[test]
    fn a_known_address_with_no_path_held_advertises_nothing() {
        let got = effective_urls(&Advertised::default(), &reflexive(false));

        assert_eq!(got.state, AdvertiseState::NoRelay, "{got:?}");
        assert!(got.urls.is_empty(), "{got:?}");
    }

    /// A confirmed direct mapping opens the gate on its own, with no relay reservation.
    ///
    /// The gate is `reserved || direct mapping`, and nothing produces the second term today — so
    /// this is the only thing that can prove the term is wired at all rather than silently lost.
    /// Paired with the case above, which fixes the same address with BOTH terms false.
    #[test]
    fn a_confirmed_direct_mapping_opens_the_gate_without_a_relay() {
        let direct = PublicAddress {
            direct_mapping: true,
            ..reflexive(false)
        };
        let got = effective_urls(&Advertised::default(), &direct);

        assert_eq!(got.state, AdvertiseState::Derived, "{got:?}");
        assert_eq!(got.urls.len(), 2, "{got:?}");
    }

    /// The operator's value wins, and wins even where the derived one would ALSO have been
    /// publishable.
    ///
    /// The address fixture is deliberately a live, derivable one. Overriding a node that could
    /// derive nothing would be satisfied identically by an implementation with no override at all.
    #[test]
    fn an_operator_value_beats_a_derivable_address() {
        let operator = parse_advertised_urls("https://mirror.example.net/dig");
        let got = effective_urls(&operator, &reflexive(true));

        assert_eq!(got.state, AdvertiseState::Override, "{got:?}");
        assert_eq!(got.urls, vec!["https://mirror.example.net/dig".to_string()]);
    }

    /// An operator value whose every entry is unpublishable does NOT quietly fall back to the
    /// derived address.
    ///
    /// They named a place. Staking their collateral on a different one because their value had a
    /// typo is a surprise about money, and the warning naming the typo is something they can act
    /// on. The address fixture is live, so the fallback this refuses is genuinely available.
    #[test]
    fn an_unpublishable_operator_value_does_not_fall_back_to_the_derived_address() {
        let operator = parse_advertised_urls("http://localhost:4161/, mirror.example.net");
        let got = effective_urls(&operator, &reflexive(true));

        assert_eq!(got.state, AdvertiseState::Off, "{got:?}");
        assert!(got.urls.is_empty(), "{got:?}");
    }

    /// A reflexive address that can only mean this machine never reaches a coin.
    ///
    /// A reading is not a promise: a seam reporting a loopback or link-local mapping must be
    /// refused exactly as an operator typing one is. The honest sibling in the same fixture is what
    /// separates this from a blanket refusal of every derived address.
    #[test]
    fn a_this_machine_reflexive_address_is_never_derived_into_a_coin() {
        let mixed = PublicAddress {
            reflexive: vec![
                "127.0.0.1:9444".parse().expect("a v4 socket address"),
                "[::1]:9444".parse().expect("a v6 socket address"),
                "169.254.10.4:9444".parse().expect("a v4 socket address"),
                "198.51.100.7:9444".parse().expect("a v4 socket address"),
            ],
            relay_reserved: true,
            direct_mapping: false,
        };
        let got = effective_urls(&Advertised::default(), &mixed);

        assert_eq!(
            got.urls,
            vec!["dig://198.51.100.7:9444".to_string()],
            "only the genuinely public mapping may survive: {got:?}"
        );

        let only_local = PublicAddress {
            reflexive: vec!["127.0.0.1:9444".parse().expect("a v4 socket address")],
            relay_reserved: true,
            direct_mapping: false,
        };
        let refused = effective_urls(&Advertised::default(), &only_local);
        assert_eq!(
            refused.state,
            AdvertiseState::NoPublicAddress,
            "a mapping that can only mean this machine is not a public address: {refused:?}"
        );
    }

    /// The adapter reads the snapshot `dig.getNetworkInfo` actually returns.
    ///
    /// `reflexive_addr` is hard-coded `null` in `dig-node-core` today, so the null case is the
    /// SHIPPED one and the string and array cases are written against the shape
    /// `dig_ecosystem#3198` will produce. Both are accepted because the producer does not exist yet
    /// to settle which; every way of being wrong drops the address, which refuses a create rather
    /// than staking one.
    #[test]
    fn the_network_info_adapter_reads_the_address_and_the_relay() {
        let null = serde_json::json!({
            "reflexive_addr": serde_json::Value::Null,
            "relay": { "reserved": true },
        });
        let read = PublicAddress::from_network_info(&null);
        assert!(read.reflexive.is_empty(), "{read:?}");
        assert!(read.relay_reserved, "{read:?}");

        let one = serde_json::json!({
            "reflexive_addr": "198.51.100.7:9444",
            "relay": { "reserved": false },
        });
        let read = PublicAddress::from_network_info(&one);
        assert_eq!(read.reflexive.len(), 1, "{read:?}");
        assert!(!read.relay_reserved, "{read:?}");

        let many = serde_json::json!({
            "reflexive_addr": ["[2001:db8::1]:9444", "198.51.100.7:9444", "not an address"],
            "relay": { "reserved": true },
        });
        let read = PublicAddress::from_network_info(&many);
        assert_eq!(
            read.reflexive.len(),
            2,
            "an unparseable entry is dropped, not fatal: {read:?}"
        );
    }

    /// `reachability` is NOT evidence of a direct mapping, and must never be read as one.
    ///
    /// It reports `"direct"` whenever no relay is in use — the ABSENCE of a relay, not evidence of
    /// reachability. An adapter that read it would make the liveness gate vacuously true for every
    /// non-relayed node, which is precisely the population the gate exists to stop advertising.
    #[test]
    fn a_reachability_of_direct_is_not_read_as_a_confirmed_mapping() {
        let not_relayed = serde_json::json!({
            "reflexive_addr": "198.51.100.7:9444",
            "reachability": "direct",
            "relay": { "reserved": false },
        });
        let read = PublicAddress::from_network_info(&not_relayed);

        assert!(!read.direct_mapping, "{read:?}");
        assert!(
            !read.is_live(),
            "a node with no relay and no confirmed mapping is not live: {read:?}"
        );
        assert_eq!(
            effective_urls(&Advertised::default(), &read).state,
            AdvertiseState::NoRelay
        );
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
