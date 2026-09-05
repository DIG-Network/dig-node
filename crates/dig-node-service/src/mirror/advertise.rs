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
//! # The derived value is checked before it can reach a coin, because a source can lie without erroring
//!
//! This value goes **into a coin, on chain, permanently**, with collateral locked behind it for an
//! epoch, so it faces two gates an operator's typed value does not:
//!
//! 1. **AGREEMENT** — [`PublicAddress::corroborated_addresses`]. Two DIFFERENT sources must report
//!    the same address. `relay.dig.net` answers STUN, and for an **IPv4** caller it returns its load
//!    balancer's SNAT'd IPv6 address with a synthetic port rather than the caller's own
//!    (`relay.dig.net#11`, fixed by `relay.dig.net#12`) — well-formed every time, correct magic
//!    cookie, matching transaction id, a routable address that serves nothing. Nothing errors, so no
//!    amount of checking ONE answer sees it, and dig-node prefers the relay tier. It is NC-12's
//!    shape (untrusted sources that must agree, never one that is trusted) applied to the node's
//!    reading of itself.
//! 2. **ROUTABILITY** — [`is_globally_routable`]. A derived private, CGNAT, documentation,
//!    benchmarking or reserved address is a broken reading rather than a choice, and is refused.
//!    An operator's LAN address is still accepted, because that IS a choice (§25.10).
//!
//! # Two things that are NOT rejection criteria, because getting either wrong is expensive
//!
//! **The address FAMILY is never one.** `relay.dig.net#11` is an address-family CROSSING defect, not
//! an IPv6 one: an IPv6 caller gets the correct answer 3 times out of 3, and only an IPv4 caller
//! gets the balancer's address — `preserve_client_ip` is mandatory for UDP ip-target groups, and AWS
//! documents it as having no effect on traffic converted from IPv6 to IPv4. So IPv6 is both the
//! WORKING case and the §5.2-preferred one, and a rule shaped as "distrust IPv6 from the relay"
//! would discard good discovery while keeping the bad answers. This module ORDERS by family
//! ([`derived_urls`]) and never judges by it.
//!
//! **Ownership is never one either.** Blocking the AWS block that surfaced `relay.dig.net#11` would
//! paper over one instance of a general defect and would be wrong for every node legitimately
//! running on EC2. Agreement catches a wrong-but-routable answer; an allowlist would not.
//!
//! # What this layer deliberately does NOT check — dig-node#566
//!
//! The sharpest discriminator is **whether the answer describes the caller**: a reported port equal
//! to the querying socket's own source port, and a reported family matching the transport queried
//! over. Both belong to the STUN CLIENT, which knows its own socket; neither is visible here, where
//! the only input is an address someone reported.
//!
//! **The port equality check must not be lifted naively to this layer**, because a NAT'd node's
//! reflexive port legitimately differs from its local source port — that is what NAT port mapping
//! IS — so `reported_port == source_port` applied here would refuse exactly the population this
//! feature exists to serve. It is a real signal where the source port is known and the comparison is
//! per-query; it is a trap where it is not.
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

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

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
    /// An address no stranger on the open internet could route to — a private, shared/CGNAT,
    /// documentation, benchmarking or reserved range.
    ///
    /// **Reachable only from the DERIVED path, and deliberately so.** §25.10 lets an OPERATOR
    /// publish a LAN address: they made a deliberate choice and risk only their own stake. A
    /// derived one is never a choice, only a broken reading of this node's own position.
    NotGloballyRoutable,
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
    pub const ALL: [Rejection; 3] = [
        Rejection::NotAbsolute,
        Rejection::ThisMachineOnly,
        Rejection::NotGloballyRoutable,
    ];
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

/// The precedence [`advertised_urls_from_env`] applies, pure over already-read inputs so it is
/// unit-testable without process env mutation or a real config path — the same "drive the pure
/// decision with fixture data, let the impure wrapper do the reading" split this module's own
/// [`effective_urls`] already uses:
///
/// 1. **The live environment variable, when non-blank.** A deploy/CI export must never be
///    silently shadowed by a saved control-plane choice — the same precedence `Config::from_env`'s
///    upstream resolution already uses.
/// 2. **Else the persisted override**, written by `control.config.setMirrorAdvertiseUrls`
///    (dig-node#570). This is what makes that call's `requires_restart: true` promise genuine:
///    nothing can rewrite a running process's own environment, but the NEXT process start reads
///    this precedence fresh and picks the persisted value up.
/// 3. **Else nothing.**
fn advertised_urls_precedence(env_value: Option<String>, persisted: Option<Vec<String>>) -> Advertised {
    if let Some(v) = env_value.filter(|v| !v.trim().is_empty()) {
        return parse_advertised_urls(&v);
    }
    match persisted {
        Some(urls) => parse_advertised_urls(&urls.join(",")),
        None => Advertised::default(),
    }
}

/// [`advertised_urls_from_env`] for an explicit config path (tests) — see that function for the
/// precedence this implements.
pub fn advertised_urls_effective_from(config_path: &std::path::Path) -> Advertised {
    advertised_urls_precedence(
        std::env::var(ADVERTISE_URLS_ENV).ok(),
        crate::control::read_mirror_advertise_urls_override_from(config_path),
    )
}

/// Reads the operator's advertised-URL list: the live environment variable when set, else the
/// persisted `control.config.setMirrorAdvertiseUrls` override (dig-node#570) — see
/// [`advertised_urls_precedence`] for the exact rule and why the override is honoured here at all.
pub fn advertised_urls_from_env() -> Advertised {
    advertised_urls_effective_from(&dig_node_core::config_path())
}

/// The URL scheme a derived entry is published under.
///
/// Deliberately NOT `http`. `DIG_NODE_PORT` (9778) is the HTTP content port and it is
/// LOOPBACK-BOUND by default (see [`crate::config`]), so a relay cannot mediate it and a stranger
/// cannot reach it. What a stranger genuinely reaches is the dig-peer mTLS wire, which is the socket
/// the reflexive mapping is OF — so the derived URL names that transport rather than one this node
/// is not serving to the outside world. [`classify`] accepts a non-special scheme on purpose.
const DERIVED_SCHEME: &str = "dig";

/// One reading of this node's public address, and WHO reported it.
///
/// The source travels with the address because a single reporter cannot be checked. A STUN server
/// that answers promptly, with the right magic cookie, a matching transaction id and a well-formed
/// `XOR-MAPPED-ADDRESS` can still be reporting the wrong address, and nothing about the exchange
/// says so — measured on `relay.dig.net` (`relay.dig.net#11`), whose NLB SNATs an IPv4 caller's UDP
/// flow, so the relay honestly reports the only peer it can then see: itself. Every answer
/// well-formed; the same server answers an IPv6 caller correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reflexive {
    /// An opaque label for whoever reported it — a relay endpoint, a public STUN server.
    ///
    /// Compared only for INEQUALITY, so this module never has to know what the labels mean. Two
    /// readings corroborate each other exactly when their sources differ and their addresses match.
    pub source: String,
    /// The address that source said this node appears at.
    pub addr: SocketAddr,
}

/// What this node knows about where a stranger could reach it, as one pass reads it.
///
/// A plain value with no behaviour of its own beyond [`Self::is_live`] and
/// [`Self::corroborated_addresses`], so the decision below is pure over it and a test supplies a
/// whole world in three fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicAddress {
    /// Every reading of this node's public address, each with its reporter — the NAT mappings of
    /// THIS node's dig-peer socket, carrying their own ports.
    ///
    /// A list rather than one address for two reasons: a dual-stack node can have a mapping per
    /// family, and an address is only usable once TWO reporters agree on it. Ordering here is
    /// whatever the seam reported; [`derived_urls`] is what puts IPv6 first (CLAUDE.md §5.2).
    pub reflexive: Vec<Reflexive>,
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

    /// The addresses at least TWO DIFFERENT sources reported, in first-seen order.
    ///
    /// # Why agreement, and not a better single source
    ///
    /// Because a wrong answer from one source is indistinguishable from a right one. `relay.dig.net`
    /// answers STUN, and for an IPv4 caller returns its own load balancer's address rather than the
    /// caller's (`relay.dig.net#11`): well-formed every time, correct magic cookie, matching
    /// transaction id, a routable global-unicast address that serves nothing. Nothing errors, so no
    /// amount of checking ONE answer catches it. A second, independent source disagrees immediately.
    ///
    /// Agreement is the right shape precisely BECAUSE it does not depend on knowing what is wrong.
    /// The first diagnosis of that defect was "the relay reports its balancer's address"; the real
    /// one is narrower — an address-family crossing that leaves IPv6 callers correctly served. A
    /// guard aimed at the first reading would have rejected good answers and kept bad ones.
    /// Agreement is indifferent to which reading was right.
    ///
    /// This matters here more than anywhere else in the node, because this value is written **into
    /// a coin, on chain, permanently**, with collateral locked behind it for an epoch.
    ///
    /// It is the shape NC-12 already asks for — untrusted sources that must AGREE, never one that is
    /// trusted — applied to the node's reading of its own address.
    ///
    /// # What this deliberately does NOT do
    ///
    /// It does not know what any source IS. No range is special-cased, and in particular no AWS
    /// range is: blocking `2600:1f00::/24` would paper over one instance of a general defect and
    /// would be wrong for every node legitimately running on EC2, which many will.
    pub fn corroborated_addresses(&self) -> Vec<SocketAddr> {
        let mut agreed: Vec<SocketAddr> = Vec::new();
        for reading in &self.reflexive {
            let confirmed = self
                .reflexive
                .iter()
                .any(|other| other.addr == reading.addr && other.source != reading.source);
            if confirmed && !agreed.contains(&reading.addr) {
                agreed.push(reading.addr);
            }
        }
        agreed
    }

    /// Reads one pass's view out of `dig.getNetworkInfo`'s answer.
    ///
    /// The `reflexive_addr` key is accepted in three shapes, and anything that does not parse is
    /// dropped. `dig-node-core` publishes the `[{"source", "addr"}]` shape once a STUN tier has
    /// answered (dig-node#567); the tolerance for the other two shapes stays regardless, since a
    /// future producer — or a hand-built test fixture — is still free to use them, and every one
    /// of the three is handled identically here: only the named-source array can corroborate.
    ///
    /// | shape | read as |
    /// |---|---|
    /// | `"1.2.3.4:9444"` | ONE reading from one unnamed source |
    /// | `["…", "…"]` | several readings, all from the SAME unnamed source |
    /// | `[{"source": "…", "addr": "…"}]` | one reading per named source |
    ///
    /// **The first two can never be corroborated**, and that is the point rather than a limitation:
    /// a list of bare strings carries no provenance, and two entries from one reporter are not two
    /// reporters agreeing. A producer that wants its address advertised must say who reported it.
    ///
    /// Every way of being wrong about the shape fails in the same direction — no corroborated
    /// address, so no create — which costs an epoch's rewards rather than money.
    pub fn from_network_info(info: &serde_json::Value) -> Self {
        /// The label given to a reading that arrived without provenance. One shared label, so two
        /// such readings can never corroborate each other.
        const UNNAMED: &str = "";

        let reading = |source: &str, raw: &str| {
            raw.parse::<SocketAddr>().ok().map(|addr| Reflexive {
                source: source.to_string(),
                addr,
            })
        };
        let reflexive = match &info["reflexive_addr"] {
            serde_json::Value::String(one) => reading(UNNAMED, one).into_iter().collect(),
            serde_json::Value::Array(many) => many
                .iter()
                .filter_map(|entry| match entry {
                    serde_json::Value::String(raw) => reading(UNNAMED, raw),
                    other => reading(
                        other["source"].as_str().unwrap_or(UNNAMED),
                        other["addr"].as_str()?,
                    ),
                })
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
    ///
    /// Covers both "nothing has reported one" and "what was reported is not a public address" — a
    /// mapping that names this machine, a private range or a documentation range is not knowledge
    /// of where a stranger reaches this node.
    NoPublicAddress,
    /// Exactly one source reported an address, and nothing has confirmed it.
    ///
    /// Distinct from [`Self::NoPublicAddress`] because the remedy differs: this node is not missing
    /// an answer, it is missing a SECOND one. See [`PublicAddress::corroborated_addresses`] for why
    /// one is not enough.
    Uncorroborated,
    /// A public address is known, but no path to this node is currently held.
    NoRelay,
}

impl AdvertiseState {
    /// Every variant, so the operator-message guard walks the SET rather than a chosen example.
    ///
    /// Declared beside the enum for the same reason [`Rejection::ALL`] is: a walk assembled inside
    /// the test would still compile and still pass after a variant was added, shipping the new
    /// state's line unguarded by the very test written to guard it.
    pub const ALL: [AdvertiseState; 6] = [
        AdvertiseState::Override,
        AdvertiseState::Derived,
        AdvertiseState::Off,
        AdvertiseState::NoPublicAddress,
        AdvertiseState::Uncorroborated,
        AdvertiseState::NoRelay,
    ];

    /// The machine-readable name, as §25.10's state taxonomy spells it.
    pub fn label(self) -> &'static str {
        match self {
            AdvertiseState::Override => "advertising_override",
            AdvertiseState::Derived => "advertising_derived",
            AdvertiseState::Off => "off",
            AdvertiseState::NoPublicAddress => "no_public_address",
            AdvertiseState::Uncorroborated => "uncorroborated_address",
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
            // Names the missing SECOND source, because that is the whole of the remedy and it is
            // not something the operator does. A sentence about configuring or connecting would
            // send them at the wrong thing entirely.
            AdvertiseState::Uncorroborated => {
                "only one source has reported a public address for this node and nothing has \
                 confirmed it, so it is not advertising mirrors and not earning; a single source \
                 can be wrong without erroring"
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
    /// Addresses this node DERIVED and then refused, each with the reason.
    ///
    /// Carried out rather than dropped inside the decision, because otherwise an operator whose
    /// node keeps deriving an unusable address is told only `no_public_address`, with no way to
    /// learn that one WAS reported and what was wrong with it. The caller logs these on a state
    /// change; the decision itself stays pure and silent.
    ///
    /// Always empty in the [`AdvertiseState::Override`] and [`AdvertiseState::Off`] states — an
    /// operator entry\'s own rejections are reported once at bring-up by
    /// [`configured_operator_urls`], and reporting them again every pass would say the same thing
    /// for ever.
    pub rejected: Vec<(String, Rejection)>,
}

impl Default for Effective {
    /// Nothing advertised, for the reason that is true before anything has been read.
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            state: AdvertiseState::NoPublicAddress,
            rejected: Vec::new(),
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
///    reflexive address — still reachable on a relay-less/offline host, or one whose STUN walk
///    (`dig_ecosystem#3198`/#561) has never answered (dig-node#567 wires that discovery into
///    `dig.getNetworkInfo`; it does not guarantee a tier answers).
pub fn effective_urls(operator: &Advertised, address: &PublicAddress) -> Effective {
    if operator.can_advertise() {
        return Effective {
            urls: operator.accepted.clone(),
            state: AdvertiseState::Override,
            ..Effective::default()
        };
    }
    if !operator.rejected.is_empty() {
        return Effective {
            state: AdvertiseState::Off,
            ..Effective::default()
        };
    }

    let agreed = address.corroborated_addresses();
    if agreed.is_empty() {
        // WHICH kind of nothing. "No source has spoken" and "one source has spoken and nothing
        // confirms it" are different conditions with different remedies, and the second is the one
        // a node sits in while a broken STUN server answers it confidently.
        return Effective {
            state: if address.reflexive.is_empty() {
                AdvertiseState::NoPublicAddress
            } else {
                AdvertiseState::Uncorroborated
            },
            ..Effective::default()
        };
    }

    let derived = derived_urls(&agreed);
    if !derived.can_advertise() {
        return Effective {
            state: AdvertiseState::NoPublicAddress,
            rejected: derived.rejected,
            ..Effective::default()
        };
    }
    if !address.is_live() {
        return Effective {
            state: AdvertiseState::NoRelay,
            rejected: derived.rejected,
            ..Effective::default()
        };
    }
    Effective {
        urls: derived.accepted,
        state: AdvertiseState::Derived,
        rejected: derived.rejected,
    }
}

/// This node's own corroborated addresses as publishable URLs, IPv6 first.
///
/// Two gates, and the derived path is STRICTER than the operator's on purpose:
///
/// * [`is_globally_routable`], which an operator entry does NOT face. §25.10 lets an operator
///   publish a LAN address, because they made a deliberate choice and risk only their own stake. A
///   DERIVED private, shared, documentation or reserved address is never a choice — it is a broken
///   reading of this node's own position, and staking an epoch on it is not something anyone asked
///   for.
/// * [`classify`], the same gate the operator's entries pass, which also catches a socket that does
///   not render as a parseable URL at all.
///
/// A reflexive address is a reading, not a promise. That is why it arrives here already agreed
/// between two sources ([`PublicAddress::corroborated_addresses`]) and still has to clear both.
fn derived_urls(agreed: &[SocketAddr]) -> Advertised {
    let (v6, v4): (Vec<&SocketAddr>, Vec<&SocketAddr>) =
        agreed.iter().partition(|addr| addr.is_ipv6());

    let mut out = Advertised::default();
    for addr in v6.into_iter().chain(v4) {
        // `SocketAddr`'s own rendering already brackets an IPv6 host and carries the port, so this
        // is the one place the URL form is spelled and there is no second way to write it.
        let url = format!("{DERIVED_SCHEME}://{addr}");
        if !is_globally_routable(*addr) {
            out.rejected.push((url, Rejection::NotGloballyRoutable));
            continue;
        }
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

/// Whether an address is one a stranger on the open internet could route to.
///
/// The rule is on what the address DENOTES, never on who owns it. **No provider range is
/// special-cased and none ever should be** — blocking the AWS block that `relay.dig.net#11`
/// produced would paper over one instance of a general defect and would be wrong for every node
/// legitimately running on EC2, which many will. That defect is caught by AGREEMENT
/// ([`PublicAddress::corroborated_addresses`]), which is where it belongs; this function catches the
/// different and simpler class of a reading that is not a public address at all.
///
/// An IPv6 address that merely WRAPS an IPv4 one is judged by the address it embeds, for the same
/// reason [`classify`] does it: the meaning of a mapped or compatible form lives entirely in its low
/// 32 bits.
fn is_globally_routable(addr: SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => is_globally_routable_v4(v4),
        std::net::IpAddr::V6(v6) => match v6.to_ipv4() {
            Some(embedded) => is_globally_routable_v4(embedded),
            None => is_globally_routable_v6(v6),
        },
    }
}

/// The IPv4 half. Every excluded range is named, because a bare predicate list is unreviewable.
fn is_globally_routable_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — RFC 5737, for documents and nothing else.
        || ip.is_documentation()
        // 0.0.0.0/8, "this network". Also what `::1` unwraps to (`0.0.0.1`), so this arm is what
        // stops the IPv6 loopback surviving the embedded-v4 unwrap above.
        || a == 0
        // 100.64.0.0/10 — RFC 6598 carrier-grade NAT. A node given one of these is behind a second
        // layer of NAT and is not reachable at it.
        || (a == 100 && (64..128).contains(&b))
        // 198.18.0.0/15 — RFC 2544 benchmarking.
        || (a == 198 && (b == 18 || b == 19))
        // 192.0.0.0/24 — IETF protocol assignments.
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        // 240.0.0.0/4 reserved, which also covers 255.255.255.255.
        || a >= 240)
}

/// The IPv6 half.
fn is_globally_routable_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // fe80::/10 link-local. `is_unicast_link_local` is unstable, so the prefix is tested here.
        || (seg[0] & 0xffc0) == 0xfe80
        // fc00::/7 unique-local — RFC 4193, the IPv6 analogue of a private range.
        || (seg[0] & 0xfe00) == 0xfc00
        // 2001:db8::/32 — RFC 3849 documentation.
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)
        // 2001:2::/48 — RFC 5180 benchmarking.
        || (seg[0] == 0x2001 && seg[1] == 0x0002 && seg[2] == 0x0000)
        // 100::/64 — RFC 6666 discard-only.
        || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0))
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
        Rejection::NotGloballyRoutable => concat!(
            "this node derived an address no stranger could route to, which is a ",
            "broken reading of where it sits rather than a place to stake an epoch on",
        ),
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

/// The whole line an operator sees when an address this node DERIVED is dropped.
///
/// A separate wrapper from [`not_advertised`], not a shared one: two of the three rejections are
/// reachable from BOTH paths, so the subject cannot be chosen from the reason. Naming
/// `DIG_MIRROR_ADVERTISE_URLS` for an address the node derived would point an operator at a setting
/// that had nothing to do with it.
pub fn not_derived(reason: &str) -> String {
    format!("this node's own derived address is not advertised: {reason}")
}

/// The operator-facing line for one derived rejection, ready to log.
///
/// Public because the scheduler is what emits it — the decision stays pure and silent, and reports
/// once on a state change rather than every pass.
pub fn derived_rejection_line(why: &Rejection) -> String {
    not_derived(rejection_reason(why))
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

    // -- Persisted mirror-advertise-URLs override precedence (dig-node#570) -------------------
    // Pure over already-read inputs (no env mutation, no filesystem), the same testing style
    // every other decision in this module uses.

    /// The live environment variable wins outright when non-blank, regardless of what a
    /// persisted override holds — a deploy/CI export must never be silently shadowed by a saved
    /// control-plane choice.
    #[test]
    fn the_env_value_wins_over_a_persisted_override_when_present() {
        let result = advertised_urls_precedence(
            Some("https://env.example".to_string()),
            Some(vec!["https://persisted.example".to_string()]),
        );
        assert_eq!(result.accepted, vec!["https://env.example".to_string()]);
    }

    /// No env value at all: the persisted override is used — this is what makes
    /// `control.config.setMirrorAdvertiseUrls`'s `requires_restart: true` promise become true the
    /// next time the process starts.
    #[test]
    fn a_persisted_override_is_used_when_the_env_var_is_absent() {
        let result =
            advertised_urls_precedence(None, Some(vec!["https://persisted.example".to_string()]));
        assert_eq!(result.accepted, vec!["https://persisted.example".to_string()]);
    }

    /// A BLANK env value (set but empty/whitespace) counts as absent, not as an explicit "advertise
    /// nothing" — matching `SetMirrorAdvertiseUrlsParams::validated`'s own refusal of an explicit
    /// empty list: this module has no way to tell "unset" from "set to nothing" through a bare env
    /// string, so it reads a blank the same permissive way it always has.
    #[test]
    fn a_blank_env_value_falls_back_to_the_persisted_override_too() {
        let result = advertised_urls_precedence(
            Some("   ".to_string()),
            Some(vec!["https://persisted.example".to_string()]),
        );
        assert_eq!(result.accepted, vec!["https://persisted.example".to_string()]);
    }

    /// Neither present: nothing to advertise, exactly `Advertised::default()` — the situation
    /// every real dig-node is in before this override was ever set.
    #[test]
    fn neither_env_nor_persisted_yields_nothing() {
        let result = advertised_urls_precedence(None, None);
        assert_eq!(result, Advertised::default());
    }

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
            .flat_map(|why| {
                let name = match why {
                    Rejection::NotAbsolute => "Rejection::NotAbsolute",
                    Rejection::ThisMachineOnly => "Rejection::ThisMachineOnly",
                    Rejection::NotGloballyRoutable => "Rejection::NotGloballyRoutable",
                };
                // BOTH wrappers, not the bare reason: those are the lines an operator actually
                // reads, and each contains the reason, so this covers all three. Walking only one
                // wrapper would leave the other path's sentence — the one whose subject differs —
                // unchecked while the guard claimed to cover every line this module emits.
                [
                    (name, not_advertised(rejection_reason(why))),
                    (name, not_derived(rejection_reason(why))),
                ]
            })
            // Every state's sentence too, driven from its own `ALL` for the same reason. Five of
            // this module's operator-facing lines now live behind `AdvertiseState::reason`, and
            // `ADVERTISING_AT_CONFIGURED_URLS` is reached through the `Override` arm rather than
            // named separately, so no line is walked twice and none is missed.
            .chain(
                AdvertiseState::ALL
                    .iter()
                    .map(|state| (state.label(), state.reason())),
            )
            .collect();

        assert_eq!(
            lines.len(),
            Rejection::ALL.len() * 2 + AdvertiseState::ALL.len(),
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

    /// A global-unicast IPv4 address. NOT `198.51.100.x`: that is RFC 5737 documentation space,
    /// which the derived path now refuses, so the obvious test address would make every fixture
    /// here pass for the wrong reason.
    const PUBLIC_V4: &str = "93.184.216.34:9444";
    /// A global-unicast IPv6 address. NOT `2001:db8::`, for the same reason.
    const PUBLIC_V6: &str = "[2606:4700:4700::1111]:9444";

    /// One reading of `addr`, attributed to `source`.
    fn seen(source: &str, addr: &str) -> Reflexive {
        Reflexive {
            source: source.to_string(),
            addr: addr.parse().expect("a socket address"),
        }
    }

    /// A node whose address two independent sources agree on, IPv4 listed first so the IPv6-first
    /// ordering assertion cannot pass by accident.
    fn reflexive(relay_reserved: bool) -> PublicAddress {
        PublicAddress {
            reflexive: vec![
                seen("relay", PUBLIC_V4),
                seen("stun.example", PUBLIC_V4),
                seen("relay", PUBLIC_V6),
                seen("stun.example", PUBLIC_V6),
            ],
            relay_reserved,
            direct_mapping: false,
        }
    }

    /// With an address two sources agree on and a relay held, the node advertises its own peer
    /// socket — IPv6 first, in `dig://` form.
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
            vec![format!("dig://{PUBLIC_V6}"), format!("dig://{PUBLIC_V4}")],
            "the derived list must name the dig-peer wire, IPv6 first: {got:?}"
        );
        assert!(got.can_advertise());
    }

    /// **One source is never enough, however confident it is.**
    ///
    /// This is the `relay.dig.net#11` case exactly: a STUN server answering ten times out of ten,
    /// every answer well-formed, every answer the address of its own load balancer rather than the
    /// caller's. Nothing about that exchange errors, so a node checking the ANSWER cannot see it —
    /// only a second, independent source can. dig-node prefers the relay tier, so this is the
    /// answer a node gets today, and without this gate it would go into a coin on chain.
    ///
    /// The state is `Uncorroborated`, not `NoPublicAddress`: this node is not missing an answer,
    /// it is missing a second one, and those have different remedies.
    #[test]
    fn one_source_is_never_enough_however_confident_it_is() {
        let single = PublicAddress {
            // Ten identical readings, all from the SAME reporter. Ten of one source is one source.
            reflexive: (0..10).map(|_| seen("relay", PUBLIC_V4)).collect(),
            relay_reserved: true,
            direct_mapping: false,
        };
        let got = effective_urls(&Advertised::default(), &single);

        assert_eq!(got.state, AdvertiseState::Uncorroborated, "{got:?}");
        assert!(got.urls.is_empty(), "{got:?}");
    }

    /// Two sources that DISAGREE corroborate neither address.
    ///
    /// The control for the case above: agreement must mean the addresses match, not merely that
    /// two sources spoke. Without this, a broken relay beside a working public server would publish
    /// both answers — including the wrong one.
    #[test]
    fn two_sources_that_disagree_corroborate_neither() {
        let split = PublicAddress {
            reflexive: vec![
                // What a SNAT'ing load balancer reports: its own address, well-formed and routable.
                seen("relay", "[2600:1f18:11a9::1]:9444"),
                seen("stun.example", PUBLIC_V6),
            ],
            relay_reserved: true,
            direct_mapping: false,
        };
        let got = effective_urls(&Advertised::default(), &split);

        assert_eq!(got.state, AdvertiseState::Uncorroborated, "{got:?}");
        assert!(
            got.urls.is_empty(),
            "neither address is agreed, so neither may be staked on: {got:?}"
        );
    }

    /// **No provider range is special-cased.** An address inside AWS's block is published like any
    /// other once two sources agree on it.
    ///
    /// The same `2600:1f18:…` prefix the broken relay reported. Blocking it would paper over one
    /// instance of a general defect and would be wrong for every node legitimately running on EC2,
    /// which many will. Agreement is what separates the two cases — never ownership.
    #[test]
    fn a_provider_range_is_not_special_cased_when_two_sources_agree_on_it() {
        let on_ec2 = PublicAddress {
            reflexive: vec![
                seen("relay", "[2600:1f18:11a9::1]:9444"),
                seen("stun.example", "[2600:1f18:11a9::1]:9444"),
            ],
            relay_reserved: true,
            direct_mapping: false,
        };
        let got = effective_urls(&Advertised::default(), &on_ec2);

        assert_eq!(got.state, AdvertiseState::Derived, "{got:?}");
        assert_eq!(got.urls, vec!["dig://[2600:1f18:11a9::1]:9444".to_string()]);
    }

    /// **An IPv6 reflexive address is never refused for being IPv6.**
    ///
    /// `relay.dig.net#11` is an address-family CROSSING defect: the same server answers an IPv6
    /// caller correctly and an IPv4 caller with its balancer's address. IPv6 is therefore both the
    /// working case and the §5.2-preferred one, so a fix shaped as "distrust IPv6 from the relay"
    /// would throw away good discovery and keep the bad answers. This pins the rule such a fix
    /// would break, using an IPv6 address in the very range that surfaced the defect.
    #[test]
    fn an_ipv6_address_is_never_refused_for_being_ipv6() {
        let v6_only = PublicAddress {
            reflexive: vec![
                seen("relay", "[2600:1f18:11a9::1]:9444"),
                seen("stun.example", "[2600:1f18:11a9::1]:9444"),
            ],
            relay_reserved: true,
            direct_mapping: false,
        };
        let got = effective_urls(&Advertised::default(), &v6_only);

        assert_eq!(got.state, AdvertiseState::Derived, "{got:?}");
        assert_eq!(got.urls, vec!["dig://[2600:1f18:11a9::1]:9444".to_string()]);
    }

    /// No reflexive address at all means no advertisement — and the reason names the ADDRESS, never
    /// the operator's configuration.
    ///
    /// This remains a real state on a relay-less/offline host, or one whose STUN walk has never
    /// answered (dig-node#567 wires the discovery `dig_ecosystem#3198`/#561 already produces into
    /// `dig.getNetworkInfo`; it does not make discovery infallible). Telling an operator in that
    /// state to configure something would send them to a remedy that cannot work.
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
    /// Distinct from the two cases above on purpose: waiting for an address, waiting for a second
    /// opinion and waiting for a connection have three different remedies, and collapsing them into
    /// one empty list is what makes an operator chase the wrong thing.
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
    /// The address fixture is deliberately a live, agreed, derivable one. Overriding a node that
    /// could derive nothing would be satisfied identically by an implementation with no override at
    /// all.
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
    /// on. The address fixture is live and agreed, so the fallback this refuses is genuinely
    /// available.
    #[test]
    fn an_unpublishable_operator_value_does_not_fall_back_to_the_derived_address() {
        let operator = parse_advertised_urls("http://localhost:4161/, mirror.example.net");
        let got = effective_urls(&operator, &reflexive(true));

        assert_eq!(got.state, AdvertiseState::Off, "{got:?}");
        assert!(got.urls.is_empty(), "{got:?}");
    }

    /// A derived address outside global unicast never reaches a coin, whatever agrees on it.
    ///
    /// Two sources agreeing on a private address are two sources agreeing on a broken reading. The
    /// walk covers each excluded class rather than one example of one of them, and the global
    /// control below is what separates this from a blanket refusal of every derived address.
    #[test]
    fn a_derived_address_outside_global_unicast_is_refused() {
        for bad in [
            "127.0.0.1:9444",         // loopback
            "[::1]:9444",             // loopback, reached through the embedded-v4 unwrap
            "169.254.10.4:9444",      // link-local
            "192.168.1.9:9444",       // private
            "10.0.0.5:9444",          // private
            "100.64.0.9:9444",        // RFC 6598 carrier-grade NAT
            "198.51.100.7:9444",      // RFC 5737 documentation
            "198.18.0.9:9444",        // RFC 2544 benchmarking
            "240.0.0.9:9444",         // reserved
            "0.0.0.0:9444",           // unspecified
            "[2001:db8::1]:9444",     // RFC 3849 documentation
            "[fc00::1]:9444",         // RFC 4193 unique-local
            "[fe80::1]:9444",         // link-local
            "[::ffff:10.0.0.5]:9444", // a private v4 wrapped in v6
        ] {
            let refused = PublicAddress {
                reflexive: vec![seen("relay", bad), seen("stun.example", bad)],
                relay_reserved: true,
                direct_mapping: false,
            };
            let got = effective_urls(&Advertised::default(), &refused);
            assert_eq!(
                got.state,
                AdvertiseState::NoPublicAddress,
                "{bad} is not an address a stranger can route to: {got:?}"
            );
            assert!(got.urls.is_empty(), "{bad}: {got:?}");
        }

        // The control. The same shape with a genuinely global address publishes, so the walk above
        // is refusing these addresses rather than refusing everything.
        let good = PublicAddress {
            reflexive: vec![seen("relay", PUBLIC_V4), seen("stun.example", PUBLIC_V4)],
            relay_reserved: true,
            direct_mapping: false,
        };
        assert_eq!(
            effective_urls(&Advertised::default(), &good).urls,
            vec![format!("dig://{PUBLIC_V4}")]
        );
    }

    /// The routability rule is asymmetric ON PURPOSE: an operator may publish a LAN address that
    /// the derived path refuses.
    ///
    /// §25.10 allows it because a LAN deployment is a deliberate operator choice risking only their
    /// own stake. A DERIVED LAN address is never a choice. Asserting both halves in one place is
    /// what stops a later tidy-up unifying them and silently taking the operator's option away.
    #[test]
    fn an_operator_may_publish_a_lan_address_the_derived_path_refuses() {
        let operator = parse_advertised_urls("http://192.168.1.9:4161/");
        assert_eq!(
            effective_urls(&operator, &PublicAddress::default()).state,
            AdvertiseState::Override,
            "an operator's LAN address is a choice they are allowed to make"
        );

        let derived = PublicAddress {
            reflexive: vec![
                seen("relay", "192.168.1.9:9444"),
                seen("stun.example", "192.168.1.9:9444"),
            ],
            relay_reserved: true,
            direct_mapping: false,
        };
        assert_eq!(
            effective_urls(&Advertised::default(), &derived).state,
            AdvertiseState::NoPublicAddress,
            "the same address DERIVED is a broken reading, not a choice"
        );
    }

    /// A this-machine mapping is dropped while its genuinely public sibling survives.
    ///
    /// A reading is not a promise: a seam reporting a loopback or link-local mapping must be
    /// refused exactly as an operator typing one is. The honest sibling in the same fixture is what
    /// separates this from a blanket refusal of every derived address.
    #[test]
    fn a_this_machine_reflexive_address_is_never_derived_into_a_coin() {
        let mut readings = Vec::new();
        for bad in ["127.0.0.1:9444", "[::1]:9444", "169.254.10.4:9444"] {
            readings.push(seen("relay", bad));
            readings.push(seen("stun.example", bad));
        }
        readings.push(seen("relay", PUBLIC_V4));
        readings.push(seen("stun.example", PUBLIC_V4));

        let got = effective_urls(
            &Advertised::default(),
            &PublicAddress {
                reflexive: readings,
                relay_reserved: true,
                direct_mapping: false,
            },
        );

        assert_eq!(
            got.urls,
            vec![format!("dig://{PUBLIC_V4}")],
            "only the genuinely public mapping may survive: {got:?}"
        );
    }

    /// The adapter reads the snapshot `dig.getNetworkInfo` actually returns, in all three shapes.
    ///
    /// `null` remains a real, shipped state (a relay-less/offline host, or one no STUN tier has
    /// ever answered); `dig-node-core` publishes the named-source array once a tier does answer
    /// (dig-node#567). All three shapes stay accepted here regardless, and the two that carry no
    /// provenance can never corroborate — a bare list is one reporter repeating itself, not two
    /// reporters agreeing.
    #[test]
    fn the_network_info_adapter_reads_the_address_the_provenance_and_the_relay() {
        let null = serde_json::json!({
            "reflexive_addr": serde_json::Value::Null,
            "relay": { "reserved": true },
        });
        let read = PublicAddress::from_network_info(&null);
        assert!(read.reflexive.is_empty(), "{read:?}");
        assert!(read.relay_reserved, "{read:?}");

        let one = serde_json::json!({
            "reflexive_addr": PUBLIC_V4,
            "relay": { "reserved": false },
        });
        let read = PublicAddress::from_network_info(&one);
        assert_eq!(read.reflexive.len(), 1, "{read:?}");
        assert!(!read.relay_reserved, "{read:?}");
        assert!(
            read.corroborated_addresses().is_empty(),
            "one unnamed reading is not two reporters agreeing: {read:?}"
        );

        let bare_list = serde_json::json!({
            "reflexive_addr": [PUBLIC_V4, PUBLIC_V4, "not an address"],
            "relay": { "reserved": true },
        });
        let read = PublicAddress::from_network_info(&bare_list);
        assert_eq!(
            read.reflexive.len(),
            2,
            "an unparseable entry is dropped, not fatal: {read:?}"
        );
        assert!(
            read.corroborated_addresses().is_empty(),
            "a list of bare strings carries no provenance, so it can never corroborate: {read:?}"
        );

        let attributed = serde_json::json!({
            "reflexive_addr": [
                { "source": "relay.dig.net", "addr": PUBLIC_V6 },
                { "source": "stun.example", "addr": PUBLIC_V6 },
                { "source": "relay.dig.net", "addr": "not an address" },
            ],
            "relay": { "reserved": true },
        });
        let read = PublicAddress::from_network_info(&attributed);
        assert_eq!(
            read.corroborated_addresses(),
            vec![PUBLIC_V6.parse::<SocketAddr>().expect("a socket address")],
            "two named sources agreeing is the one shape that corroborates: {read:?}"
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
            "reflexive_addr": [
                { "source": "relay.dig.net", "addr": PUBLIC_V4 },
                { "source": "stun.example", "addr": PUBLIC_V4 },
            ],
            "reachability": "direct",
            "relay": { "reserved": false },
        });
        let read = PublicAddress::from_network_info(&not_relayed);

        assert!(!read.direct_mapping, "{read:?}");
        assert!(
            !read.is_live(),
            "a node with no relay and no confirmed mapping is not live: {read:?}"
        );
        // Reaching the LIVENESS gate is what proves the address itself was fine, so the refusal is
        // the one under test rather than an earlier one standing in for it.
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
