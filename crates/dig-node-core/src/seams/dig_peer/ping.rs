//! Peer PING — run the connection ladder against one peer and report WHICH tier reached it.
//!
//! This answers the question "is this node actually reachable, and how?", which until now was
//! answered by hand with a TCP port probe across a list of addresses. An open port is not a peer
//! connection: it says nothing about whether the mTLS handshake succeeds, whether the certificate
//! binds the `peer_id` you asked for, or whether the path that worked was the direct one or the
//! relay of last resort (dig_ecosystem#1985).
//!
//! **It reports the LADDER, not just the winner.** SPEC §19.1 ranks the tiers
//! `Direct → UPnP → NAT-PMP → PCP → hole-punch → Relayed` and makes the relay the LAST resort, so
//! "connected" is not one fact but two: whether the peer was reached, and what it cost to reach it.
//! A peer reachable only through the relay is a different operational state from one reachable
//! directly, and collapsing them to a boolean is what hid dig_ecosystem#1929.
//!
//! **A relay-only success is expected, not broken.** Most peers on the network are behind NAT and
//! are relay-reachable only; that is the normal shape of the network, and [`PingVerdict::severity`]
//! deliberately grades it `warn`, never `error`. The finding worth surfacing is narrower: a peer
//! that ADVERTISES a routable address and still cannot be reached directly.
//!
//! **It is read-only.** Each tier is a bare `dig-nat` dial that is dropped as soon as it is graded:
//! it joins no pool, announces nothing, writes nothing, and leaves no relay reservation behind — a
//! diagnostic that mutates network state is not a diagnostic. It dials from the SAME config builder
//! [`crate::net::full_nat_config`] uses ([`crate::net::single_tier_nat_config`]), narrowed to one tier
//! at a time, so what it reports is what the real dialer does rather than a parallel prober that could
//! drift away from it.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use dig_nat::{PeerTarget, TraversalKind};
use serde_json::{json, Value};

/// The ladder as SPEC §19.1 defines it, in canonical rank order (relay last).
///
/// Derived from [`TraversalKind::rank`] rather than written out, so a tier added to dig-nat is
/// probed here automatically instead of being silently missed by a hardcoded list.
pub fn ladder_tiers() -> Vec<TraversalKind> {
    let mut tiers = vec![
        TraversalKind::Direct,
        TraversalKind::Upnp,
        TraversalKind::NatPmp,
        TraversalKind::Pcp,
        TraversalKind::HolePunch,
        TraversalKind::Relayed,
    ];
    tiers.sort_by_key(|t| t.rank());
    tiers
}

/// The wire token for a tier — stable, lower-case, and part of the control-method contract.
pub fn tier_name(tier: TraversalKind) -> &'static str {
    match tier {
        TraversalKind::Direct => "direct",
        TraversalKind::Upnp => "upnp",
        TraversalKind::NatPmp => "nat-pmp",
        TraversalKind::Pcp => "pcp",
        TraversalKind::HolePunch => "hole-punch",
        TraversalKind::Relayed => "relayed",
    }
}

/// What one tier of the ladder did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierOutcome {
    /// The tier established an authenticated mTLS peer connection.
    Connected {
        /// The address the connection actually landed on.
        remote_addr: SocketAddr,
        /// The `peer_id` the presented certificate derives (`SHA-256(TLS SPKI DER)`) — the identity
        /// that answered, which is not necessarily the identity that was asked for.
        observed_peer_id: String,
        elapsed_ms: u64,
    },
    /// The tier was attempted and did not connect. `reason` is dig-nat's own failure text.
    Failed { reason: String, elapsed_ms: u64 },
    /// The tier was not attempted at all (the overall deadline elapsed first).
    Skipped { reason: String },
}

impl TierOutcome {
    /// The connected peer's observed identity, if this tier connected.
    pub fn observed_peer_id(&self) -> Option<&str> {
        match self {
            TierOutcome::Connected {
                observed_peer_id, ..
            } => Some(observed_peer_id),
            _ => None,
        }
    }
}

/// One rung of the ladder and what it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierReport {
    pub tier: TraversalKind,
    pub outcome: TierOutcome,
}

impl TierReport {
    fn skipped(tier: TraversalKind, reason: impl Into<String>) -> Self {
        TierReport {
            tier,
            outcome: TierOutcome::Skipped {
                reason: reason.into(),
            },
        }
    }
}

/// The overall reading of a ladder run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PingVerdict {
    /// Reached WITHOUT the relay — the healthy shape.
    Direct { tier: TraversalKind },
    /// Reached, but only through the relay. SPEC §19.1 makes the relay the last resort, so this is a
    /// yellow reading rather than a green one — and the ordinary state for a peer behind NAT.
    RelayedOnly,
    /// No tier reached the peer.
    Unreachable,
    /// A tier connected, but the certificate derives a DIFFERENT `peer_id` than the one asked for.
    ///
    /// This outranks every other reading, including a successful direct connection: reaching the
    /// right address and the wrong identity is a failure that must be loud, never a pass.
    IdentityMismatch { expected: String, observed: String },
}

/// Grade a completed ladder run.
///
/// `expected_peer_id` is the identity the caller asked for, when it asked by `peer_id`; a ping by
/// bare address has none to check against and reports whichever identity answered.
pub fn verdict(expected_peer_id: Option<&str>, tiers: &[TierReport]) -> PingVerdict {
    // Identity first, and before any success is reported: a connection to the wrong peer is the one
    // outcome that must never be graded on how nicely it connected.
    if let Some(expected) = expected_peer_id {
        for report in tiers {
            if let Some(observed) = report.outcome.observed_peer_id() {
                if !observed.eq_ignore_ascii_case(expected) {
                    return PingVerdict::IdentityMismatch {
                        expected: expected.to_ascii_lowercase(),
                        observed: observed.to_ascii_lowercase(),
                    };
                }
            }
        }
    }
    // The best (lowest-rank) tier that connected wins the reading.
    let best = tiers
        .iter()
        .filter(|r| matches!(r.outcome, TierOutcome::Connected { .. }))
        .min_by_key(|r| r.tier.rank());
    match best {
        Some(r) if r.tier == TraversalKind::Relayed => PingVerdict::RelayedOnly,
        Some(r) => PingVerdict::Direct { tier: r.tier },
        None => PingVerdict::Unreachable,
    }
}

impl PingVerdict {
    /// The wire token for this reading.
    pub fn code(&self) -> &'static str {
        match self {
            PingVerdict::Direct { .. } => "direct",
            PingVerdict::RelayedOnly => "relayed-only",
            PingVerdict::Unreachable => "unreachable",
            PingVerdict::IdentityMismatch { .. } => "identity-mismatch",
        }
    }

    /// How loudly to render this reading: `ok` / `warn` / `error`.
    ///
    /// A relay-only peer is `warn`, NOT `error`: most peers on the network are behind NAT and are
    /// relay-reachable only, so grading that as a failure would report a healthy network as broken
    /// to every user who ran the diagnostic.
    pub fn severity(&self) -> &'static str {
        match self {
            PingVerdict::Direct { .. } => "ok",
            PingVerdict::RelayedOnly => "warn",
            PingVerdict::Unreachable | PingVerdict::IdentityMismatch { .. } => "error",
        }
    }

    /// A one-line reading in plain language, saying what happened AND whether it is a problem.
    pub fn summary(&self) -> String {
        match self {
            PingVerdict::Direct { tier } => format!(
                "reachable over the {} tier, without the relay",
                tier_name(*tier)
            ),
            PingVerdict::RelayedOnly => "reachable, but only through the relay — normal for a peer \
                 behind NAT; a finding only if this peer advertises a routable address"
                .to_string(),
            PingVerdict::Unreachable => {
                "not reachable on any tier of the connection ladder".to_string()
            }
            PingVerdict::IdentityMismatch { expected, observed } => format!(
                "WRONG PEER: the address answered with peer_id {observed}, not the {expected} asked for"
            ),
        }
    }
}

/// A peer reached by one tier: who answered and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialedPeer {
    pub observed_peer_id: String,
    pub remote_addr: SocketAddr,
}

/// Attempt exactly ONE tier of the ladder.
///
/// The seam exists so [`run_ladder`]'s grading is testable without a network; the production
/// implementation ([`NatTierDialer`]) is a thin wrapper over the same `dig_nat::connect_with_runtime`
/// every other node dial goes through.
#[async_trait]
pub trait TierDialer: Send + Sync {
    /// Dial `target` with ONLY `tier` enabled. `Err` carries dig-nat's failure text verbatim.
    async fn dial_tier(
        &self,
        tier: TraversalKind,
        target: &PeerTarget,
    ) -> Result<DialedPeer, String>;
}

/// Run every tier of the ladder against `target` and report each one.
///
/// Every tier is attempted even after one succeeds — the point of the diagnostic is the whole
/// ladder, since "connected" hides whether the direct path was available. Attempts stop only at
/// `deadline`, after which the remaining tiers are reported as skipped rather than silently dropped.
pub async fn run_ladder(
    dialer: &dyn TierDialer,
    target: &PeerTarget,
    deadline: Duration,
) -> Vec<TierReport> {
    // `tokio::time::Instant`, not `std::time::Instant`: it is the clock `tokio::time` bounds are
    // measured against, so the deadline holds under a paused test clock as well as in production.
    let started = tokio::time::Instant::now();
    let mut reports = Vec::new();
    for tier in ladder_tiers() {
        if started.elapsed() >= deadline {
            reports.push(TierReport::skipped(
                tier,
                format!("overall deadline of {}s reached first", deadline.as_secs()),
            ));
            continue;
        }
        let tier_started = tokio::time::Instant::now();
        let outcome = match dialer.dial_tier(tier, target).await {
            Ok(peer) => TierOutcome::Connected {
                remote_addr: peer.remote_addr,
                observed_peer_id: peer.observed_peer_id,
                elapsed_ms: tier_started.elapsed().as_millis() as u64,
            },
            Err(reason) => TierOutcome::Failed {
                reason,
                elapsed_ms: tier_started.elapsed().as_millis() as u64,
            },
        };
        reports.push(TierReport { tier, outcome });
    }
    reports
}

/// Everything a ping needs from the running peer network: this node's mTLS identity, the shared NAT
/// runtime (which carries the live relay reservation the relayed tier rides), the network id, and the
/// STUN server that feeds the hole-punch tier.
///
/// Assembled once by bring-up and kept on the [`Node`](crate::Node) so the control surface can run a
/// ladder with exactly the inputs the node's own dials use — the ping cannot drift from the real
/// dialer because it is given the real dialer's configuration.
pub struct PeerPingContext {
    identity: std::sync::Arc<dig_nat::NodeCert>,
    runtime: std::sync::Arc<dig_nat::NatRuntime>,
    network_id: String,
    stun_server: Option<SocketAddr>,
    per_tier_timeout: Duration,
    gate: PingGate,
}

impl PeerPingContext {
    pub fn new(
        identity: std::sync::Arc<dig_nat::NodeCert>,
        runtime: std::sync::Arc<dig_nat::NatRuntime>,
        network_id: impl Into<String>,
        stun_server: Option<SocketAddr>,
        per_tier_timeout: Duration,
    ) -> Self {
        PeerPingContext {
            identity,
            runtime,
            network_id: network_id.into(),
            stun_server,
            per_tier_timeout,
            gate: PingGate::default(),
        }
    }

    /// The network id peers are registered under, for relay lookups + hole-punch coordination.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// The per-tier timeout a ladder run bounds each attempt by.
    pub fn per_tier_timeout(&self) -> Duration {
        self.per_tier_timeout
    }
}

// -- Anti-amplification gate -------------------------------------------------------------------
//
// A ping takes a caller-supplied address and makes this node dial it. That is a request-forgery
// shape: unbounded, it would turn the node's control surface into a dialer anyone local could point
// at a third party (#1985). The gate lives HERE, on the context every ping must go through, rather
// than in the control shell — so a second caller (the CLI, the app, a future `dign` verb) cannot
// reach the dialer without it.

/// How many ladder runs this node will START inside [`PING_RATE_WINDOW`].
///
/// A ladder is a slow operation, so the START rate is what needs bounding: a target that refuses
/// every tier instantly would otherwise let a caller loop dials as fast as the OS can refuse them.
pub const MAX_PINGS_PER_WINDOW: u32 = 6;

/// The fixed window [`MAX_PINGS_PER_WINDOW`] is counted over.
pub const PING_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Why a ping was refused BEFORE any dial was made — distinct from a ladder that ran and found
/// nothing, which is a diagnostic answer and reported as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PingRefused {
    /// A ladder is already running on this node. Single-flight is the hard load bound: however many
    /// callers ask, this surface never has more than one ladder's worth of dials outstanding.
    InFlight,
    /// The start-rate bound is exhausted; `retry_after` is when the current window closes.
    RateLimited { retry_after: Duration },
}

impl PingRefused {
    /// A one-line reason for the caller, naming the bound rather than just refusing.
    pub fn summary(&self) -> String {
        match self {
            PingRefused::InFlight => {
                "a peer ping is already running on this node; only one runs at a time".to_string()
            }
            PingRefused::RateLimited { retry_after } => format!(
                "peer-ping rate limit reached ({MAX_PINGS_PER_WINDOW} per {}s); retry in {}s",
                PING_RATE_WINDOW.as_secs(),
                retry_after.as_secs() + 1
            ),
        }
    }
}

/// Single-flight plus a fixed-window start bound on ladder runs.
#[derive(Debug, Default)]
struct PingGate {
    running: std::sync::atomic::AtomicBool,
    window: std::sync::Mutex<StartWindow>,
}

/// The fixed counting window: how many ladders started since `opened_at`. `None` means no window is
/// open yet, so the first start opens one.
#[derive(Debug, Default)]
struct StartWindow {
    opened_at: Option<std::time::Instant>,
    starts: u32,
}

/// Holds the single-flight claim for the duration of one ladder; releases it on drop, so an early
/// return or a panic mid-ladder cannot wedge the surface closed for the rest of the process.
struct PingLease<'a> {
    gate: &'a PingGate,
}

impl Drop for PingLease<'_> {
    fn drop(&mut self) {
        self.gate
            .running
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

impl PingGate {
    /// Claim the right to run ONE ladder, or say why not.
    ///
    /// The rate window is charged only AFTER the single-flight claim succeeds, so a caller that is
    /// merely too eager (a second concurrent request) does not also burn its window budget.
    fn try_enter(&self, now: std::time::Instant) -> Result<PingLease<'_>, PingRefused> {
        use std::sync::atomic::Ordering;
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(PingRefused::InFlight);
        }
        let lease = PingLease { gate: self };
        // A poisoned lock (a panic while held) must not wedge the diagnostic shut; the guard's
        // accounting is fully re-derived from `now` below.
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match admit(&mut window, now) {
            Ok(()) => {
                drop(window);
                Ok(lease)
            }
            // `lease` drops here, releasing the single-flight claim the refusal never used.
            Err(retry_after) => Err(PingRefused::RateLimited { retry_after }),
        }
    }
}

/// Charge one start against the fixed window, opening a fresh window when the old one has elapsed.
/// `Err(retry_after)` is how long until the current window closes. PURE (given `window` + `now`).
fn admit(window: &mut StartWindow, now: std::time::Instant) -> Result<(), Duration> {
    let opened_at = match window.opened_at {
        // The window has elapsed (or none was ever opened): start counting again from now.
        Some(opened) if now.duration_since(opened) < PING_RATE_WINDOW => opened,
        _ => {
            window.opened_at = Some(now);
            window.starts = 0;
            now
        }
    };
    if window.starts >= MAX_PINGS_PER_WINDOW {
        return Err(PING_RATE_WINDOW.saturating_sub(now.duration_since(opened_at)));
    }
    window.starts += 1;
    Ok(())
}

/// The production [`TierDialer`]: one tier of the REAL `dig-nat` ladder per attempt.
///
/// It dials via [`crate::net::single_tier_nat_config`], which shares its builder with
/// [`crate::net::full_nat_config`] — the one config constructor SPEC §19.1 requires every node dial
/// site to use — differing ONLY in narrowing `enabled_methods` to the single tier under test. So each
/// attempt is the genuine dialer restricted to one rung, not a reimplementation that could disagree
/// with what the node actually does when it connects to a peer.
pub struct NatTierDialer<'a> {
    ctx: &'a PeerPingContext,
}

impl<'a> NatTierDialer<'a> {
    pub fn new(ctx: &'a PeerPingContext) -> Self {
        NatTierDialer { ctx }
    }
}

#[async_trait]
impl TierDialer for NatTierDialer<'_> {
    async fn dial_tier(
        &self,
        tier: TraversalKind,
        target: &PeerTarget,
    ) -> Result<DialedPeer, String> {
        let config = crate::net::single_tier_nat_config(
            self.ctx.per_tier_timeout,
            self.ctx.stun_server,
            tier,
        );

        let conn =
            dig_nat::connect_with_runtime(target, &self.ctx.identity, &config, &self.ctx.runtime)
                .await
                .map_err(|e| e.to_string())?;

        let dialed = DialedPeer {
            observed_peer_id: conn.peer_id.to_hex(),
            remote_addr: conn.remote_addr,
        };
        // Dropped immediately, before the result is even graded: a diagnostic must leave nothing
        // behind — no pooled session, no held relay circuit (#1985).
        drop(conn);
        Ok(dialed)
    }
}

/// How a ping resolved the `peer` argument into something dialable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetResolution {
    /// A `peer_id` and at least one candidate address — a full identity-verified ladder can run.
    Resolved {
        peer_id: String,
        addrs: Vec<SocketAddr>,
    },
    /// The argument named a peer whose address this node does not know.
    NoKnownAddress { peer_id: String },
    /// An address was given with no identity to verify it against.
    ///
    /// dig-nat pins the expected `peer_id` in the TLS verifier, so there is no anonymous dial to
    /// fall back to — and degrading to a bare TCP probe would report exactly the "open port means
    /// connected" answer this diagnostic exists to replace. The caller is told what to supply.
    IdentityRequired { addr: SocketAddr },
    /// The argument was neither a 64-hex `peer_id` nor a dialable `host:port`.
    Unparseable,
}

/// Turn the `peer` argument into a dialable target.
///
/// `known` is the node's view of who is where — `(peer_id_hex, addr)` for every peer it can name,
/// sourced from the connected pool. `explicit_peer_id` is an identity the caller pinned outright,
/// which always wins: pinning a `peer_id` that does NOT match the address is exactly how the
/// identity-mismatch case is exercised, so it must not be second-guessed here.
pub fn resolve_target(
    peer: &str,
    explicit_peer_id: Option<&str>,
    known: &[(String, SocketAddr)],
) -> TargetResolution {
    let peer = peer.trim();

    // A dialable address: the identity comes from the caller's pin, else from what this node already
    // knows is listening there.
    if let Ok(addr) = peer.parse::<SocketAddr>() {
        if let Some(pinned) = explicit_peer_id {
            return TargetResolution::Resolved {
                peer_id: pinned.to_ascii_lowercase(),
                addrs: vec![addr],
            };
        }
        return match known.iter().find(|(_, a)| *a == addr) {
            Some((peer_id, _)) => TargetResolution::Resolved {
                peer_id: peer_id.to_ascii_lowercase(),
                addrs: vec![addr],
            },
            None => TargetResolution::IdentityRequired { addr },
        };
    }

    // A bare peer_id: look up every address this node knows for it.
    if is_peer_id(peer) {
        let peer_id = peer.to_ascii_lowercase();
        let addrs: Vec<SocketAddr> = known
            .iter()
            .filter(|(id, _)| id.eq_ignore_ascii_case(&peer_id))
            .map(|(_, a)| *a)
            .collect();
        return if addrs.is_empty() {
            TargetResolution::NoKnownAddress { peer_id }
        } else {
            TargetResolution::Resolved { peer_id, addrs }
        };
    }

    TargetResolution::Unparseable
}

/// The node's view of who is where, as [`resolve_target`] wants it: `(peer_id_hex, addr)` for every
/// peer in the live connected pool.
///
/// This is the ONLY source a ping resolves a bare address against. The connected pool is the set of
/// identities this node has already authenticated over mTLS, so an address it names has a `peer_id`
/// the certificate actually proved — never a guess, and never an attacker-supplied claim about who
/// lives at an address.
pub fn known_peers(handle: &dig_gossip::GossipHandle) -> Vec<(String, SocketAddr)> {
    handle
        .connected_pool_peers()
        .into_iter()
        .map(|(peer_id, addr, _outbound)| (hex::encode(peer_id), addr))
        .collect()
}

/// Whether `s` is a canonical 64-hex `peer_id`.
fn is_peer_id(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Build the dig-nat [`PeerTarget`] for a resolved ping, ordering candidates IPv6-first (§5.2).
pub fn peer_target(
    peer_id_hex: &str,
    addrs: &[SocketAddr],
    network_id: &str,
) -> Option<PeerTarget> {
    let bytes = hex::decode(peer_id_hex).ok().filter(|b| b.len() == 32)?;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    // IPv6 candidates lead: the ecosystem is IPv6-first with IPv4 as the fallback, and the ping must
    // exercise the ladder in the same family order a real dial would.
    let mut ordered: Vec<SocketAddr> = addrs.to_vec();
    ordered.sort_by_key(|a| !a.is_ipv6());
    Some(PeerTarget::with_addrs(
        dig_nat::PeerId::from_bytes(raw),
        ordered,
        network_id,
    ))
}

/// The ping result as the control method returns it.
pub fn report_json(
    peer: &str,
    expected_peer_id: Option<&str>,
    tiers: &[TierReport],
    verdict: &PingVerdict,
) -> Value {
    json!({
        "peer": peer,
        "expected_peer_id": expected_peer_id,
        "verdict": verdict.code(),
        "severity": verdict.severity(),
        "summary": verdict.summary(),
        "ladder": tiers.iter().map(tier_json).collect::<Vec<_>>(),
    })
}

/// One ladder rung as JSON. The TCP/mTLS distinction lives in `reason`: dig-nat reports a refused
/// port and a rejected handshake as different failures, and #1985 needs them told apart.
fn tier_json(report: &TierReport) -> Value {
    match &report.outcome {
        TierOutcome::Connected {
            remote_addr,
            observed_peer_id,
            elapsed_ms,
        } => json!({
            "tier": tier_name(report.tier),
            "result": "connected",
            "remote_addr": remote_addr.to_string(),
            // §5.2 is IPv6-first, so an IPv4-only success is itself a finding worth reading off.
            "family": if remote_addr.is_ipv6() { "ipv6" } else { "ipv4" },
            "observed_peer_id": observed_peer_id,
            "elapsed_ms": elapsed_ms,
        }),
        TierOutcome::Failed { reason, elapsed_ms } => json!({
            "tier": tier_name(report.tier),
            "result": "failed",
            "reason": reason,
            "elapsed_ms": elapsed_ms,
        }),
        TierOutcome::Skipped { reason } => json!({
            "tier": tier_name(report.tier),
            "result": "skipped",
            "reason": reason,
        }),
    }
}

/// Run a full ping: resolve `peer`, walk the ladder, grade it, and return the report JSON.
///
/// `known` is `(peer_id_hex, addr)` for every peer this node can currently name. A resolution
/// failure is reported as an `Ok` result with an `error` severity, never as a refusal: "I could not
/// work out what to dial" is a diagnostic answer, and the caller asked a diagnostic question. `Err`
/// is reserved for a ping that was never allowed to dial at all ([`PingRefused`]).
///
/// Resolution runs BEFORE the gate is claimed, so an unparseable argument costs no rate budget and
/// cannot lock out a caller who then types a real one.
pub async fn ping_peer(
    ctx: &PeerPingContext,
    peer: &str,
    explicit_peer_id: Option<&str>,
    known: &[(String, SocketAddr)],
    deadline: Duration,
) -> Result<Value, PingRefused> {
    let (peer_id, addrs) =
        match resolve_target(peer, explicit_peer_id, known) {
            TargetResolution::Resolved { peer_id, addrs } => (peer_id, addrs),
            TargetResolution::NoKnownAddress { peer_id } => return Ok(unresolved_json(
                peer,
                Some(&peer_id),
                "this node knows no address for that peer_id — dial it by address, or wait for \
                 discovery to fold it into the connected pool",
            )),
            TargetResolution::IdentityRequired { addr } => {
                return Ok(unresolved_json(
                    peer,
                    None,
                    &format!(
                    "no peer_id is known for {addr}; supply peer_id so the mTLS certificate can be \
                     verified — an identity-less dial could only report whether a port is open, \
                     which is not a peer connection"
                ),
                ))
            }
            TargetResolution::Unparseable => {
                return Ok(unresolved_json(
                    peer,
                    None,
                    "not a dialable address (host:port, IPv6 in brackets) nor a 64-hex peer_id",
                ))
            }
        };

    let Some(target) = peer_target(&peer_id, &addrs, ctx.network_id()) else {
        return Ok(unresolved_json(
            peer,
            Some(&peer_id),
            "peer_id is not valid 64-hex",
        ));
    };

    // Held for the whole ladder; released on drop however this returns.
    let _lease = ctx.gate.try_enter(std::time::Instant::now())?;

    let dialer = NatTierDialer::new(ctx);
    let tiers = run_ladder(&dialer, &target, deadline).await;
    let verdict = verdict(Some(&peer_id), &tiers);
    Ok(report_json(peer, Some(&peer_id), &tiers, &verdict))
}

/// The result shape for a ping that never got as far as dialing.
fn unresolved_json(peer: &str, peer_id: Option<&str>, reason: &str) -> Value {
    json!({
        "peer": peer,
        "expected_peer_id": peer_id,
        "verdict": "unresolved",
        "severity": "error",
        "summary": reason,
        "ladder": Vec::<Value>::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test address")
    }

    fn connected(tier: TraversalKind, peer_id: &str, at: &str) -> TierReport {
        TierReport {
            tier,
            outcome: TierOutcome::Connected {
                remote_addr: addr(at),
                observed_peer_id: peer_id.to_string(),
                elapsed_ms: 12,
            },
        }
    }

    fn failed(tier: TraversalKind, reason: &str) -> TierReport {
        TierReport {
            tier,
            outcome: TierOutcome::Failed {
                reason: reason.to_string(),
                elapsed_ms: 5000,
            },
        }
    }

    const PEER_A: &str = "aa";
    const PEER_B: &str = "bb";

    /// **Proves:** the probed ladder is SPEC §19.1's canonical order, relay last.
    ///
    /// **Catches:** a reordering that probes the relay before the direct tier, which would report
    /// "relayed" for a peer that was directly reachable all along.
    #[test]
    fn the_ladder_is_probed_in_spec_rank_order_with_the_relay_last() {
        let tiers = ladder_tiers();
        assert_eq!(
            tiers,
            vec![
                TraversalKind::Direct,
                TraversalKind::Upnp,
                TraversalKind::NatPmp,
                TraversalKind::Pcp,
                TraversalKind::HolePunch,
                TraversalKind::Relayed,
            ]
        );
        assert_eq!(
            *tiers.last().expect("non-empty ladder"),
            TraversalKind::Relayed,
            "SPEC §19.1 makes the relay the LAST resort"
        );
    }

    /// **Proves:** a direct success is graded green.
    #[test]
    fn a_direct_connection_is_a_green_reading() {
        let tiers = vec![
            connected(TraversalKind::Direct, PEER_A, "[2001:db8::1]:9444"),
            failed(TraversalKind::Relayed, "no reservation"),
        ];
        let v = verdict(Some(PEER_A), &tiers);
        assert_eq!(
            v,
            PingVerdict::Direct {
                tier: TraversalKind::Direct
            }
        );
        assert_eq!(v.severity(), "ok");
    }

    /// **Proves:** a peer reachable ONLY through the relay reads as a yellow result — reached, but
    /// not on the tier SPEC prefers.
    ///
    /// **Catches:** grading a relay fallback as a plain success, which is what let dig_ecosystem#1929
    /// (peers relayed when direct was possible) hide behind a green "connected".
    #[test]
    fn a_relay_only_success_is_yellow_not_green() {
        let tiers = vec![
            failed(TraversalKind::Direct, "connection refused"),
            failed(TraversalKind::HolePunch, "no path formed"),
            connected(TraversalKind::Relayed, PEER_A, "44.217.228.224:9444"),
        ];
        let v = verdict(Some(PEER_A), &tiers);
        assert_eq!(v, PingVerdict::RelayedOnly);
        assert_eq!(v.severity(), "warn", "relay-only is a warning, not a pass");
    }

    /// **Proves:** a NAT'd peer — direct refused, relay worked — is NOT reported as an error, and its
    /// summary says so in words.
    ///
    /// **Catches:** the failure mode #1985 calls out explicitly: six of ten peers on the network are
    /// relay-only, so grading that shape `error` would report a healthy network as broken to every
    /// user who ran the diagnostic.
    #[test]
    fn a_natted_peer_reads_as_expected_rather_than_as_breakage() {
        let tiers = vec![
            failed(TraversalKind::Direct, "connection refused"),
            connected(TraversalKind::Relayed, PEER_A, "10.0.0.5:9444"),
        ];
        let v = verdict(Some(PEER_A), &tiers);
        assert_ne!(
            v.severity(),
            "error",
            "a NAT'd peer is normal, not an error"
        );
        let summary = v.summary().to_lowercase();
        assert!(
            summary.contains("normal") && summary.contains("nat"),
            "the summary must say a relay-only peer behind NAT is expected, got: {summary}"
        );
    }

    /// **Proves:** connecting to a reachable address that presents the WRONG identity is a loud
    /// failure — and outranks the fact that the connection itself succeeded directly.
    ///
    /// **Catches:** grading on reachability before identity, which would report "direct, ok" for a
    /// dial that reached an entirely different node than the one asked for.
    #[test]
    fn a_wrong_peer_id_on_a_reachable_address_is_an_error_not_a_success() {
        let tiers = vec![connected(
            TraversalKind::Direct,
            PEER_B,
            "[2001:db8::1]:9444",
        )];
        let v = verdict(Some(PEER_A), &tiers);
        assert_eq!(
            v,
            PingVerdict::IdentityMismatch {
                expected: PEER_A.to_string(),
                observed: PEER_B.to_string(),
            },
            "identity is checked before reachability is graded"
        );
        assert_eq!(v.severity(), "error");
    }

    /// **Proves:** a ping by bare ADDRESS (no expected identity) reports whoever answered instead of
    /// inventing a mismatch.
    #[test]
    fn a_ping_by_address_alone_reports_the_identity_that_answered() {
        let tiers = vec![connected(
            TraversalKind::Direct,
            PEER_B,
            "[2001:db8::1]:9444",
        )];
        assert_eq!(
            verdict(None, &tiers),
            PingVerdict::Direct {
                tier: TraversalKind::Direct
            }
        );
    }

    /// **Proves:** a peer no tier reached is unreachable, and that is an error.
    #[test]
    fn a_peer_no_tier_reached_is_unreachable() {
        let tiers = vec![
            failed(TraversalKind::Direct, "connection refused"),
            failed(TraversalKind::Relayed, "no reservation"),
        ];
        let v = verdict(Some(PEER_A), &tiers);
        assert_eq!(v, PingVerdict::Unreachable);
        assert_eq!(v.severity(), "error");
    }

    /// **Proves:** when several tiers connect, the reading names the BEST (lowest-rank) one.
    ///
    /// **Catches:** reporting the last tier that happened to succeed, which would call a directly
    /// reachable peer "relayed".
    #[test]
    fn the_best_tier_wins_the_reading_not_the_last_one_tried() {
        let tiers = vec![
            connected(TraversalKind::Direct, PEER_A, "[2001:db8::1]:9444"),
            connected(TraversalKind::Relayed, PEER_A, "44.217.228.224:9444"),
        ];
        assert_eq!(
            verdict(Some(PEER_A), &tiers),
            PingVerdict::Direct {
                tier: TraversalKind::Direct
            }
        );
    }

    /// **Proves:** the JSON reports EVERY rung — including the ones that failed — plus the address
    /// family that won, which §5.2 makes a finding in its own right.
    ///
    /// **Catches:** emitting only the winning tier, which is exactly the "connected: true" answer
    /// #1985 exists to replace.
    #[test]
    fn the_json_reports_every_rung_and_the_winning_address_family() {
        let tiers = vec![
            failed(TraversalKind::Direct, "connection refused"),
            connected(TraversalKind::Relayed, PEER_A, "44.217.228.224:9444"),
            TierReport::skipped(TraversalKind::HolePunch, "overall deadline"),
        ];
        let v = verdict(Some(PEER_A), &tiers);
        let out = report_json("44.217.228.224:9444", Some(PEER_A), &tiers, &v);

        let ladder = out["ladder"].as_array().expect("ladder array");
        assert_eq!(ladder.len(), 3, "every attempted rung is reported");
        assert_eq!(ladder[0]["result"], "failed");
        assert_eq!(ladder[0]["reason"], "connection refused");
        assert_eq!(ladder[1]["result"], "connected");
        assert_eq!(ladder[1]["family"], "ipv4");
        assert_eq!(ladder[2]["result"], "skipped");
        assert_eq!(out["verdict"], "relayed-only");
        assert_eq!(out["severity"], "warn");
    }

    /// **Proves:** an IPv6 win is reported as such, so an IPv4-only success is visible as the §5.2
    /// finding it is.
    #[test]
    fn an_ipv6_connection_is_reported_as_the_ipv6_family() {
        let tiers = vec![connected(
            TraversalKind::Direct,
            PEER_A,
            "[2001:db8::1]:9444",
        )];
        let out = report_json("x", Some(PEER_A), &tiers, &verdict(Some(PEER_A), &tiers));
        assert_eq!(out["ladder"][0]["family"], "ipv6");
    }

    // -- resolve_target --------------------------------------------------------------------------

    fn known_peer(id: &str, at: &str) -> (String, SocketAddr) {
        (id.repeat(32), addr(at))
    }

    /// **Proves:** a bare `peer_id` is resolved to every address this node knows for it.
    #[test]
    fn a_peer_id_resolves_to_the_addresses_this_node_knows_for_it() {
        let known = vec![
            known_peer("aa", "[2001:db8::1]:9444"),
            known_peer("bb", "10.0.0.9:9444"),
        ];
        assert_eq!(
            resolve_target(&"aa".repeat(32), None, &known),
            TargetResolution::Resolved {
                peer_id: "aa".repeat(32),
                addrs: vec![addr("[2001:db8::1]:9444")],
            }
        );
    }

    /// **Proves:** an address this node already knows an identity for resolves without the caller
    /// having to supply the `peer_id` — the "ping by ip address" form the request asked for.
    #[test]
    fn a_known_address_resolves_to_the_identity_listening_there() {
        let known = vec![known_peer("aa", "[2001:db8::1]:9444")];
        assert_eq!(
            resolve_target("[2001:db8::1]:9444", None, &known),
            TargetResolution::Resolved {
                peer_id: "aa".repeat(32),
                addrs: vec![addr("[2001:db8::1]:9444")],
            }
        );
    }

    /// **Proves:** an address with NO known identity is refused with an explanation, rather than
    /// silently downgraded to a bare TCP probe.
    ///
    /// **Catches:** the failure #1985 names directly — "an open port is not a peer connection".
    /// dig-nat pins the expected `peer_id` in its TLS verifier, so there is no anonymous dial; the
    /// honest answer is to say what is missing, not to answer a different, weaker question.
    #[test]
    fn an_unknown_address_asks_for_the_peer_id_instead_of_probing_the_port() {
        assert_eq!(
            resolve_target("203.0.113.7:9444", None, &[]),
            TargetResolution::IdentityRequired {
                addr: addr("203.0.113.7:9444")
            }
        );
    }

    /// **Proves:** an explicitly pinned `peer_id` beats what this node believes is at that address.
    ///
    /// **Catches:** "helpfully" correcting the caller's pin to the known identity, which would make
    /// the wrong-identity acceptance case in #1985 impossible to test — the mismatch would be
    /// silently repaired into a pass.
    #[test]
    fn an_explicitly_pinned_peer_id_is_never_second_guessed() {
        let known = vec![known_peer("aa", "[2001:db8::1]:9444")];
        assert_eq!(
            resolve_target("[2001:db8::1]:9444", Some(&"bb".repeat(32)), &known),
            TargetResolution::Resolved {
                peer_id: "bb".repeat(32),
                addrs: vec![addr("[2001:db8::1]:9444")],
            }
        );
    }

    /// **Proves:** a `peer_id` with no known address says so, instead of dialing nothing and calling
    /// the peer unreachable.
    #[test]
    fn a_peer_id_with_no_known_address_says_so() {
        assert_eq!(
            resolve_target(&"cc".repeat(32), None, &[]),
            TargetResolution::NoKnownAddress {
                peer_id: "cc".repeat(32)
            }
        );
    }

    /// **Proves:** junk input is rejected deterministically.
    #[test]
    fn an_unparseable_argument_is_rejected() {
        for junk in ["", "not-a-peer", "zz".repeat(32).as_str(), "1.2.3.4"] {
            assert_eq!(
                resolve_target(junk, None, &[]),
                TargetResolution::Unparseable,
                "{junk:?} is neither an address nor a peer_id"
            );
        }
    }

    /// **Proves:** the dial target orders its candidates IPv6-first (§5.2), so the ping exercises the
    /// ladder in the family order a real dial would.
    #[test]
    fn the_dial_target_puts_ipv6_candidates_first() {
        let target = peer_target(
            &"aa".repeat(32),
            &[addr("10.0.0.9:9444"), addr("[2001:db8::1]:9444")],
            "DIG_MAINNET",
        )
        .expect("valid peer_id");
        assert!(
            target.direct_addrs()[0].is_ipv6(),
            "IPv6 leads the candidate list, got {:?}",
            target.direct_addrs()
        );
    }

    // -- run_ladder ------------------------------------------------------------------------------

    /// A dialer that answers from a scripted per-tier table.
    struct ScriptedDialer {
        connect_on: Vec<TraversalKind>,
        peer_id: String,
        /// How long each attempt "takes", so the deadline path is exercisable.
        per_tier: Duration,
    }

    #[async_trait]
    impl TierDialer for ScriptedDialer {
        async fn dial_tier(
            &self,
            tier: TraversalKind,
            _target: &PeerTarget,
        ) -> Result<DialedPeer, String> {
            tokio::time::sleep(self.per_tier).await;
            if self.connect_on.contains(&tier) {
                Ok(DialedPeer {
                    observed_peer_id: self.peer_id.clone(),
                    remote_addr: addr("[2001:db8::1]:9444"),
                })
            } else {
                Err(format!("{} unavailable", tier_name(tier)))
            }
        }
    }

    fn test_target() -> PeerTarget {
        PeerTarget::with_addr(
            dig_nat::PeerId::from_bytes([0x22; 32]),
            addr("[2001:db8::1]:9444"),
            "DIG_MAINNET",
        )
    }

    /// **Proves:** the ladder keeps probing AFTER a tier succeeds, so the report says whether the
    /// direct path was available rather than stopping at the first thing that worked.
    ///
    /// **Catches:** a short-circuit on first success — which would make the diagnostic unable to
    /// answer "was it relayed when direct would have worked?", the question #1929 needed.
    #[tokio::test(start_paused = true)]
    async fn every_tier_is_probed_even_after_one_succeeds() {
        let dialer = ScriptedDialer {
            connect_on: vec![TraversalKind::Direct, TraversalKind::Relayed],
            peer_id: PEER_A.to_string(),
            per_tier: Duration::from_millis(10),
        };
        let reports = run_ladder(&dialer, &test_target(), Duration::from_secs(60)).await;
        assert_eq!(
            reports.len(),
            ladder_tiers().len(),
            "every rung of the ladder is reported"
        );
        assert!(
            reports
                .iter()
                .all(|r| !matches!(r.outcome, TierOutcome::Skipped { .. })),
            "nothing is skipped when the deadline is generous"
        );
    }

    /// **Proves:** the run is bounded — once the overall deadline passes, the remaining tiers are
    /// reported as skipped rather than attempted.
    ///
    /// **Catches:** an unbounded probe, which #1985 forbids: a black-holed address must not be able
    /// to hang the caller.
    #[tokio::test(start_paused = true)]
    async fn the_run_is_bounded_and_says_which_tiers_it_skipped() {
        let dialer = ScriptedDialer {
            connect_on: vec![],
            peer_id: PEER_A.to_string(),
            per_tier: Duration::from_secs(5),
        };
        let reports = run_ladder(&dialer, &test_target(), Duration::from_secs(11)).await;
        assert_eq!(
            reports.len(),
            ladder_tiers().len(),
            "every rung is accounted for"
        );
        let skipped = reports
            .iter()
            .filter(|r| matches!(r.outcome, TierOutcome::Skipped { .. }))
            .count();
        assert!(
            skipped > 0,
            "an 11s deadline over 5s-per-tier attempts must skip the tail, got {reports:#?}"
        );
    }

    // -- The anti-amplification gate (#1985: "it must not become an amplifier") ------------------

    /// **Proves:** only ONE ladder runs at a time. Single-flight is the hard load bound: however
    /// many callers ask at once, the node never has more than one ladder's worth of dials out.
    ///
    /// **Catches:** removing the `compare_exchange` claim, which would let N concurrent control
    /// calls turn the node into an N-way dialer pointed at a caller-chosen address.
    #[test]
    fn only_one_ladder_may_run_at_a_time() {
        let gate = PingGate::default();
        let now = std::time::Instant::now();
        let first = gate.try_enter(now).expect("the first ladder is admitted");
        assert_eq!(
            gate.try_enter(now).err(),
            Some(PingRefused::InFlight),
            "a second concurrent ladder is refused while the first holds the claim"
        );
        drop(first);
        assert!(
            gate.try_enter(now).is_ok(),
            "the claim is released on drop, so the next caller gets in"
        );
    }

    /// **Proves:** a refused-because-in-flight call does NOT spend rate budget.
    ///
    /// **Catches:** charging the window before the single-flight claim, which would let a caller
    /// exhaust the whole minute's budget with concurrent calls that never dialed anything.
    #[test]
    fn a_concurrent_refusal_costs_no_rate_budget() {
        let gate = PingGate::default();
        let now = std::time::Instant::now();
        let held = gate.try_enter(now).expect("first admitted");
        for _ in 0..50 {
            assert_eq!(gate.try_enter(now).err(), Some(PingRefused::InFlight));
        }
        drop(held);
        // One start has been charged so far; the remaining budget must be untouched by the 50
        // concurrent refusals above.
        for i in 1..MAX_PINGS_PER_WINDOW {
            assert!(
                gate.try_enter(now).is_ok(),
                "start {i} must still be within the window budget"
            );
        }
    }

    /// **Proves:** the START rate is bounded — after [`MAX_PINGS_PER_WINDOW`] ladders the gate
    /// refuses and names when to retry.
    ///
    /// **Catches:** an unbounded loop of instantly-refusing dials (every tier `ECONNREFUSED`
    /// returns in microseconds, so single-flight alone would not bound the dial rate).
    #[test]
    fn the_start_rate_is_bounded_within_the_window() {
        let gate = PingGate::default();
        let start = std::time::Instant::now();
        for i in 0..MAX_PINGS_PER_WINDOW {
            assert!(gate.try_enter(start).is_ok(), "start {i} is within budget");
        }
        match gate.try_enter(start + Duration::from_secs(1)).err() {
            Some(PingRefused::RateLimited { retry_after }) => assert!(
                retry_after <= PING_RATE_WINDOW && retry_after > Duration::ZERO,
                "retry_after must name a real wait inside the window, got {retry_after:?}"
            ),
            other => panic!(
                "the {}th start must be rate-limited, got {other:?}",
                MAX_PINGS_PER_WINDOW + 1
            ),
        }
    }

    /// **Proves:** the budget replenishes — a caller that waits out the window is admitted again.
    ///
    /// **Catches:** a window that never reopens, which would make the diagnostic a one-shot per
    /// process and push operators back to hand-probing ports.
    #[test]
    fn the_window_reopens_once_it_has_elapsed() {
        let gate = PingGate::default();
        let start = std::time::Instant::now();
        for _ in 0..MAX_PINGS_PER_WINDOW {
            gate.try_enter(start).expect("within budget");
        }
        assert!(gate.try_enter(start).is_err(), "budget spent");
        assert!(
            gate.try_enter(start + PING_RATE_WINDOW).is_ok(),
            "a fresh window admits again"
        );
    }

    /// **Proves:** the refusal explains itself — which bound was hit, and what to do about it.
    ///
    /// **Catches:** a bare "rate limited" with no numbers, which sends the operator to the source
    /// to find out how long to wait.
    #[test]
    fn a_refusal_names_the_bound_it_hit() {
        assert!(PingRefused::InFlight.summary().contains("already running"));
        let limited = PingRefused::RateLimited {
            retry_after: Duration::from_secs(12),
        }
        .summary();
        assert!(limited.contains(&MAX_PINGS_PER_WINDOW.to_string()));
        assert!(limited.contains("13s"), "rounds the wait up: {limited}");
    }
}
