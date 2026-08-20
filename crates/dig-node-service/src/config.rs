//! Runtime configuration for the dig-node service, resolved from the environment.
//!
//! The service's knobs use the canonical `DIG_NODE_*` env contract: `DIG_NODE_PORT`
//! / `DIG_NODE_HOST` pick the bind address; `DIG_RPC_UPSTREAM` picks the upstream
//! the embedded dig-node read path proxies blind ciphertext/proof requests to on a
//! cache miss.
//!
//! **STABLE ENV CONTRACT — the `DIG_NODE_*` names are the binary's canonical,
//! stable configuration contract.** The dig-installer sets them and apt.dig.net
//! documents them, so renaming them again would break those consumers.
//!
//! The upstream is wired into the read path via its own `DIG_NODE_UPSTREAM` env var
//! (see [`Config::apply_to_env`]) — the dig-node read-path crate reads that name
//! internally, so this service translates its public `DIG_RPC_UPSTREAM` knob into it.
//!
//! ## Shared `.dig` cache (#96)
//!
//! `DIG_NODE_CACHE` points the read path at the on-disk `.dig` cache. This service
//! reads it **explicitly** ([`Config::cache_dir`]) so an operator/installer can aim
//! it at one canonical cache, and re-applies it to the read path's environment in
//! [`Config::apply_to_env`].
//!
//! **Omitting it is the right default for sharing.** When `DIG_NODE_CACHE` is
//! unset, this service does NOT invent a path — it leaves the read path to resolve its
//! own canonical default (`%LOCALAPPDATA%\DigNode\cache` on Windows,
//! `$HOME/DigNode/cache` on Unix/macOS), which is **byte-identical** to the dir the
//! DIG Browser's in-process node uses. So when both the standalone service and the
//! browser are installed they share ONE cache — a capsule fetched by either is
//! served from disk by the other, with no double-store. dig-node makes that shared
//! dir safe for two processes (atomic content-addressed writes + a cross-process
//! lock; #95/#96 Pass A). Set `DIG_NODE_CACHE` only to move that shared cache
//! somewhere explicit (e.g. a service data dir, or a volume shared between
//! installs) — and set the SAME value for both the service and the browser launch
//! so they keep sharing it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Default loopback bind port — an UNCOMMON high port, deliberately clear of the
/// collision-prone common-dev ports (80/443/3000/5000/8000/8080/8888/9000) that a
/// dev machine is most likely to already have in use (#132). `9778` is the sibling
/// of the dig-wallet HTTP API's `9777` (wallet on `9777`, node on `9778`) and is the
/// port the digstore-remote §5.3 resolver already expects a local node on
/// (`DEFAULT_LOCAL_NODE_PORT`), so aligning here removes that cross-repo drift. Every
/// consumer of the §5.3 `localhost` tier (the extension's `server.host` default, the
/// installer, the DIG Browser) MUST target `9778` to match. `DIG_NODE_PORT` overrides
/// it. (`dig.local` on `127.0.0.2:80` is unaffected — only this localhost port moves.)
///
/// Single-sourced from the shared `dig-constants` crate (`DIG_NODE_PORT`) rather than
/// re-declared here, so every §5.3 client→node consumer that also imports the constant agrees
/// with this service byte-for-byte with no copy to drift.
pub const DEFAULT_PORT: u16 = dig_constants::DIG_NODE_PORT;

/// The default upstream DIG RPC: **none** (#1997).
///
/// A dig-node ships with NO upstream. A method this node does not implement answers a local
/// `-32601 METHOD_NOT_FOUND`, which is the truthful answer; passthrough is opt-in, via
/// `DIG_RPC_UPSTREAM` or the persisted `control.config.setUpstream` override.
///
/// # Why this is empty, and must stay empty
///
/// It used to be `https://rpc.dig.net`. That single default gave every node in the ecosystem three
/// properties nobody chose:
///
/// 1. **A structurally special node.** `rpc.dig.net` became load-bearing for every other node's
///    unrecognised methods, rather than an ordinary node that merely has a well-known address.
/// 2. **A silent off-box data flow.** An unrecognised method — *including its params* — was
///    forwarded to a third-party host the operator never configured. A method name is not
///    always harmless: it is caller-controlled, and its params can carry store ids and
///    retrieval keys describing what someone is reading.
/// 3. **A self-referential loop on the well-known node itself.** `rpc.dig.net`'s own node
///    inherited the default and so relayed to *itself* through its public address, turning one
///    unimplemented method into an unbounded request cycle (#1997 — the outage this fixed).
///
/// Pointing this at any other host re-creates all three with a different name. The default is the
/// absence of an upstream, not a better choice of one.
pub const DEFAULT_UPSTREAM: &str = "";

/// The loopback IP the bare-`http://dig.local` listener binds to (#91). The
/// dig-installer writes a hosts entry `127.0.0.2  dig.local`, so binding this IP on
/// the privileged port 80 makes `http://dig.local` (NO port) reach the node. A
/// distinct loopback IP (`.2`, not `.1`) is used so the port-80 bind can never
/// collide with an unrelated `localhost:80` service the user already runs. On macOS
/// the loopback alias must exist first (`sudo ifconfig lo0 alias 127.0.0.2`); the
/// installer/service handles that — see the README.
pub const DIG_LOCAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// The privileged port the bare-`http://dig.local` listener binds to (#91). Port 80
/// means the URL carries no `:port`, which is the whole point. Binding it is
/// privileged (root / `CAP_NET_BIND_SERVICE` on Linux; Administrator/LocalSystem on
/// Windows — the installed service runs elevated, so it works there). The bind is
/// BEST-EFFORT: if it fails the localhost listener still serves (see `server`).
pub const DIG_LOCAL_PORT: u16 = 80;

/// The canonical hostname the bare-`http://dig.local` listener answers to (#91).
/// Matches the dig-installer hosts entry and the extension's resolver base-domain
/// list (`dig.local` / `localhost` / `127.0.0.1`).
pub const DIG_LOCAL_HOST: &str = "dig.local";

/// The port the local HTTPS listener binds for `https://dig.local` (#624, #620 epic).
/// Port 443 means the URL carries no `:port`. Binding it is privileged like `:80`
/// (root / `CAP_NET_BIND_SERVICE`; elevated on Windows — the installed service runs
/// elevated). The bind is BEST-EFFORT and additionally GATED on a dig-cert leaf being
/// present: with no CA/leaf yet the node serves plaintext only (see `crate::tls`).
pub const DIG_LOCAL_HTTPS_PORT: u16 = 443;

/// Resolved dig-node service configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Explicit `DIG_NODE_HOST` override, or `None` for the default (#288, §5.2).
    /// `None` — the default — means "bind BOTH loopback families": `127.0.0.1`
    /// (always-on, fatal on failure) AND `[::1]` (best-effort), so `localhost`
    /// reaches the node whether the resolver returns the IPv4 or the IPv6 loopback
    /// first (Windows resolves `localhost` to `::1` first by default, which made the
    /// node appear offline to an IPv6-first client before this). `Some(ip)` — an
    /// explicit override — REPLACES the default dual bind with exactly that one
    /// address; it does not add to it. See [`Config::bind_addr`] (the primary/
    /// always-on address) and [`Config::bind_addr_v6`] (the additional IPv6
    /// loopback address, when applicable).
    pub host: Option<IpAddr>,
    /// Bind port.
    pub port: u16,
    /// Upstream DIG RPC base URL the embedded dig-node proxies to on a miss.
    pub upstream: String,
    /// Explicit on-disk cache dir for dig-node's `.dig` modules, from
    /// `DIG_NODE_CACHE`. `None` (the default) means "use dig-node's shared
    /// canonical default" — the SAME dir the DIG Browser's in-process node uses,
    /// so the two share ONE cache (see the module-level "Shared `.dig` cache"
    /// note). `Some(path)` moves that shared cache to an explicit location.
    pub cache_dir: Option<String>,
    /// Whether to ALSO open the bare-`http://dig.local` loopback listener
    /// (`127.0.0.2:80`) beside the always-on `localhost:<port>` one (#91). From
    /// `DIG_NODE_DIGLOCAL` (`1`/`true`/`yes`/`on` ⇒ enabled, `0`/`false`/… ⇒
    /// disabled); **default `true`** — auto-attempt with graceful fallback. The
    /// attempt is BEST-EFFORT: if the privileged `:80` bind fails (no privilege,
    /// port in use, or — on macOS — the `127.0.0.2` loopback alias is missing) the
    /// node logs a structured warning and serves localhost-only, never aborting.
    /// Set `DIG_NODE_DIGLOCAL=0` to skip the attempt entirely.
    pub dig_local: bool,
    /// Whether the node-custodied wallet broadcasts spends for REAL on mainnet (§18.12, #428).
    /// From `DIG_WALLET_ENABLE_LIVE_BROADCAST` (`1`/`true`/`yes`/`on` ⇒ enabled); **default
    /// `false`** — the money-safe default: no broadcaster is attached and NO $DIG moves (a tip /
    /// sign-on-behalf / send cleanly reports unavailable). When enabled, the served wallet attaches
    /// a real `chia_query` broadcaster + confirmer + lineage so node-custodied spends execute +
    /// confirm on mainnet. Enabling it means REAL $DIG movement — opt-in only.
    pub enable_live_broadcast: bool,
    /// Whether the node runs the background chain-sync supervisor (§18.6, #2501). From
    /// `DIG_WALLET_ENABLE_CHAIN_SYNC` (`0`/`false`/`no`/`off` ⇒ disabled); **default `true`** —
    /// sync is a chain READ into the node's own replica and every install wants it. It is a
    /// separate knob from [`Config::enable_live_broadcast`], which governs whether $DIG MOVES.
    ///
    /// The reason it is a knob at all is that a supervisor dials the network: it probes
    /// `127.0.0.1:8444` and then the Chia DNS introducers. A test harness must be able to build
    /// state without a shared CI runner making unrequested outbound connections — and without
    /// whatever answers on a runner's `127.0.0.1:8444` becoming a test's chain source.
    pub enable_chain_sync: bool,
    /// Whether a NON-loopback `DIG_NODE_HOST` override is permitted (#1662). From
    /// `DIG_NODE_ALLOW_REMOTE` (`1`/`true`/`yes`/`on` ⇒ permitted); **default `false`**
    /// — the security-safe default. When `false`, a non-loopback `host` is refused at
    /// startup ([`host_override_refusal`], enforced in `server::serve_with_shutdown`) so
    /// the local RPC/content API is never silently exposed to the network. Loopback
    /// overrides and the no-override dual-stack default never need this flag.
    pub allow_remote: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: None,
            port: DEFAULT_PORT,
            upstream: DEFAULT_UPSTREAM.to_string(),
            cache_dir: None,
            // Auto-attempt the bare-dig.local listener by default (graceful
            // fallback if the privileged bind fails) — see the field doc + #91.
            dig_local: true,
            // Money-safe default: live broadcast is OFF unless explicitly enabled.
            enable_live_broadcast: false,
            // Chain sync is a read into the node's own replica; on by default (#2501).
            enable_chain_sync: true,
            // Security-safe default: a non-loopback bind is opt-in only (#1662).
            allow_remote: false,
        }
    }
}

impl Config {
    /// Resolve the config from the process environment, falling back to defaults.
    /// Mirrors the stable `DIG_NODE_PORT` / `DIG_NODE_HOST` / `DIG_RPC_UPSTREAM` env
    /// contract (see the module-level "STABLE ENV CONTRACT" note).
    pub fn from_env() -> Self {
        let port = std::env::var("DIG_NODE_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|p| *p != 0)
            .unwrap_or(DEFAULT_PORT);

        let host = parse_host_override(std::env::var("DIG_NODE_HOST").ok());

        // Upstream precedence: explicit DIG_RPC_UPSTREAM env > the persisted
        // override (set via the control plane's `control.config.setUpstream`,
        // stored in dig-node's config.json) > the default. The env var still wins
        // so a deploy/CI override is never silently overridden by a saved setting;
        // the persisted value is the "I set this in the controller UI" choice that
        // takes effect on the next start (the running node captured its upstream at
        // construction — see `control.config.setUpstream` → `requires_restart`).
        let upstream = std::env::var("DIG_RPC_UPSTREAM")
            .ok()
            .map(|s| normalize_upstream(&s))
            .filter(|s| !s.is_empty())
            .or_else(|| crate::control::read_upstream_override().map(|s| normalize_upstream(&s)))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_UPSTREAM.to_string());

        // Refuse an upstream that is THIS node (#1997). Dropping it back to "no upstream" is the
        // safe resolution: relaying to ourselves can only ever loop, so declining to relay loses
        // nothing a working configuration would have provided.
        let upstream = if is_self_upstream(&upstream, port) {
            tracing::error!(
                %upstream,
                port,
                "refusing an upstream that names this node — a node cannot be its own upstream; \
                 passthrough is disabled. Set DIG_RPC_UPSTREAM to a DIFFERENT node, or leave it \
                 unset to answer unimplemented methods locally."
            );
            String::new()
        } else {
            upstream
        };

        // DIG_NODE_CACHE is read with the read path's OWN env var name (not a
        // service-specific alias) so a value the operator sets reaches the node
        // directly and this service just makes honouring it explicit. A
        // blank/whitespace value is treated as unset → shared default (see
        // resolve_cache_dir).
        let cache_dir = resolve_cache_dir(std::env::var("DIG_NODE_CACHE").ok());

        // The bare-dig.local listener is on by default (auto-attempt + graceful
        // fallback); DIG_NODE_DIGLOCAL=0/false/no/off turns it off entirely.
        let dig_local = parse_dig_local_flag(std::env::var("DIG_NODE_DIGLOCAL").ok());

        // Live mainnet broadcast is OFF unless explicitly enabled (money-safe default).
        let enable_live_broadcast =
            parse_live_broadcast_flag(std::env::var("DIG_WALLET_ENABLE_LIVE_BROADCAST").ok());

        // Chain sync is on unless explicitly turned off (a read, not a spend).
        let enable_chain_sync =
            parse_chain_sync_flag(std::env::var("DIG_WALLET_ENABLE_CHAIN_SYNC").ok());

        // A non-loopback DIG_NODE_HOST is opt-in only (#1662); enforcement happens at
        // the bind site (server::serve_with_shutdown) so `status`/`install` — which
        // never bind — still resolve the config the operator set.
        let allow_remote = parse_allow_remote_flag(std::env::var("DIG_NODE_ALLOW_REMOTE").ok());

        Config {
            host,
            port,
            upstream,
            cache_dir,
            dig_local,
            enable_live_broadcast,
            enable_chain_sync,
            allow_remote,
        }
    }

    /// Apply this config to the environment dig-node reads at `Node::from_env()`:
    ///
    /// * `DIG_NODE_UPSTREAM` ← this service's public `DIG_RPC_UPSTREAM` knob.
    ///   (dig-node deliberately uses a distinct name from the browser's
    ///   `DIG_RPC_ENDPOINT`, which points a client AT the node; reusing that would
    ///   make the node proxy to itself.)
    /// * `DIG_NODE_CACHE` ← the explicit cache dir, **only when one was set**. When
    ///   it was omitted we leave the env untouched so dig-node resolves its shared
    ///   canonical default (the dir the DIG Browser's in-process node also uses) —
    ///   writing an empty value here would instead point the node at a bogus path
    ///   and break cache sharing. See the module-level "Shared `.dig` cache" note.
    ///
    /// Called before constructing the node so both knobs are honoured.
    pub fn apply_to_env(&self) {
        std::env::set_var("DIG_NODE_UPSTREAM", &self.upstream);
        if let Some(dir) = cache_dir_env_value(self.cache_dir.as_deref()) {
            std::env::set_var("DIG_NODE_CACHE", dir);
        }
    }

    /// The socket address for the always-on localhost listener (binding / logging): the
    /// explicit `DIG_NODE_HOST` override, or the default `127.0.0.1` when unset. A bind
    /// failure on THIS address is fatal (see `server::serve_with_shutdown`) — every
    /// consumer (CLI `status`/`pair`, the installed-service summary, `/health`'s `addr`
    /// field) treats it as THE address, so its shape never changes based on the
    /// dual-stack default below.
    ///
    /// Returns a [`SocketAddr`] rather than a string so the authority can only ever be
    /// rendered by [`SocketAddr`]'s own `Display`, which brackets an IPv6 literal. The
    /// previous text-concatenated form (#1682) produced the unbracketed `::1:9778` for an
    /// IPv6 host, which is not a socket address at all — and the FATAL bind failure that
    /// followed meant configuring the family §5.2 prefers took the node down.
    pub fn bind_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.host.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            self.port,
        )
    }

    /// The IPv6 loopback bind address (`[::1]:<port>`) to open BESIDE
    /// [`Config::bind_addr`] (#288, §5.2 dual-stack loopback): `Some` when no
    /// explicit `DIG_NODE_HOST` override is set (the default — bind BOTH loopback
    /// families, since some resolvers — Windows' `localhost` by default — return
    /// `::1` before `127.0.0.1`); `None` when an explicit host override is set (it
    /// REPLACES the default dual bind with exactly that one address, rather than
    /// adding to it). This listener is BEST-EFFORT at bind time (see `serve`): an
    /// IPv6-loopback-unavailable system falls back to IPv4-only, mirroring the
    /// existing [`Config::dig_local_addr`] best-effort pattern.
    pub fn bind_addr_v6(&self) -> Option<SocketAddr> {
        self.host
            .is_none()
            .then(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), self.port))
    }

    /// The socket address for the BEST-EFFORT bare-`http://dig.local` listener
    /// (`127.0.0.2:80`), or `None` when `dig_local` is disabled (#91).
    /// `serve` tries to bind this in ADDITION to [`bind_addr`]; a failure is
    /// logged and ignored (localhost keeps serving).
    pub fn dig_local_addr(&self) -> Option<SocketAddr> {
        self.dig_local
            .then(|| SocketAddr::new(IpAddr::V4(DIG_LOCAL_IP), DIG_LOCAL_PORT))
    }

    /// The socket address for the BEST-EFFORT local HTTPS listener serving
    /// `https://dig.local` (`127.0.0.2:443`, #624), or `None` when `dig_local` is
    /// disabled. Shares the `dig_local` toggle with the plaintext `:80` listener —
    /// both are the "bare dig.local" surface, one plaintext, one TLS. The TLS listener
    /// is additionally gated on a dig-cert leaf being present (`crate::tls`); with no
    /// leaf yet only plaintext serves.
    pub fn dig_local_https_addr(&self) -> Option<SocketAddr> {
        self.dig_local
            .then(|| SocketAddr::new(IpAddr::V4(DIG_LOCAL_IP), DIG_LOCAL_HTTPS_PORT))
    }

    /// The IPv6-loopback HTTPS bind (`[::1]:443`) to open BESIDE
    /// [`Config::dig_local_https_addr`] (§5.2 IPv6-first loopback), or `None` when
    /// `dig_local` is disabled. `https://dig.local` resolves to the IPv4 alias
    /// `127.0.0.2` via the installer hosts entry, but the leaf's SAN also covers `::1`,
    /// so an IPv6 loopback client (e.g. `https://localhost` where `localhost` resolves
    /// to `::1` first) reaches the identical surface. BEST-EFFORT: a bind failure is
    /// logged and the node continues on the IPv4 listener (see `server`).
    pub fn dig_local_https_addr_v6(&self) -> Option<SocketAddr> {
        self.dig_local
            .then(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), DIG_LOCAL_HTTPS_PORT))
    }
}

/// Parse the `DIG_NODE_DIGLOCAL` toggle. Truthy (`1`/`true`/`yes`/`on`) ⇒ enable
/// the bare-dig.local listener; falsy (`0`/`false`/`no`/`off`) ⇒ disable; **unset
/// or unrecognised ⇒ the default `true`** (auto-attempt with graceful fallback).
/// Case/whitespace-insensitive. PURE so the toggle policy is unit-testable.
pub fn parse_dig_local_flag(raw: Option<String>) -> bool {
    match raw.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
        Some(ref v) if matches!(v.as_str(), "0" | "false" | "no" | "off") => false,
        Some(ref v) if matches!(v.as_str(), "1" | "true" | "yes" | "on") => true,
        // Unset, blank, or anything unrecognised → the default-on behaviour.
        _ => true,
    }
}

/// Parse the `DIG_WALLET_ENABLE_LIVE_BROADCAST` toggle (§18.12, #428). Truthy
/// (`1`/`true`/`yes`/`on`) ⇒ enable REAL mainnet broadcast; **anything else — including unset,
/// blank, or unrecognised — ⇒ the money-safe default `false`** (no $DIG moves). This is the
/// OPPOSITE default to `parse_dig_local_flag`: money movement is opt-in, never on by accident.
/// Case/whitespace-insensitive. PURE so the toggle policy is unit-testable without process env.
pub fn parse_live_broadcast_flag(raw: Option<String>) -> bool {
    matches!(
        raw.as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Parse the `DIG_WALLET_ENABLE_CHAIN_SYNC` toggle (§18.6, #2501). Falsy
/// (`0`/`false`/`no`/`off`) ⇒ do NOT start the background chain-sync supervisor; **anything else
/// — including unset, blank, or unrecognised — ⇒ the default `true`**. Default-ON, unlike
/// [`parse_live_broadcast_flag`]: syncing reads the chain into the node's own replica and moves
/// no money, so the money-safe reasoning does not apply. Case/whitespace-insensitive. PURE so the
/// policy is unit-testable without process env.
pub fn parse_chain_sync_flag(raw: Option<String>) -> bool {
    !matches!(
        raw.as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("0" | "false" | "no" | "off")
    )
}

/// Parse the `DIG_NODE_HOST` override (#288): `Some(ip)` when the raw value is a
/// valid IP literal, `None` when unset/blank/unparsable. `None` is the DEFAULT and
/// carries meaning — it is not merely "no value" — see [`Config::host`] and
/// [`Config::bind_addr_v6`]: it means "bind BOTH loopback families", not merely
/// "fall back to 127.0.0.1". PURE so the override-vs-default policy is
/// unit-testable without touching process env.
pub fn parse_host_override(raw: Option<String>) -> Option<IpAddr> {
    raw.as_deref().and_then(|s| s.trim().parse::<IpAddr>().ok())
}

/// Parse the `DIG_NODE_ALLOW_REMOTE` escape hatch (#1662): truthy
/// (`1`/`true`/`yes`/`on`) ⇒ permit a NON-loopback `DIG_NODE_HOST`; **anything else
/// — including unset, blank, or unrecognised — ⇒ the security-safe default `false`**
/// (loopback-only). Same opt-in-only shape as [`parse_live_broadcast_flag`]: exposing
/// the local RPC/content API to the network is a deliberate act, never on by accident.
/// Case/whitespace-insensitive. PURE so the policy is unit-testable without process env.
pub fn parse_allow_remote_flag(raw: Option<String>) -> bool {
    matches!(
        raw.as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Whether `ip` is a loopback address — the SHARED loopback predicate for the whole
/// service. Beyond the stdlib [`IpAddr::is_loopback`] it also treats an IPv4-MAPPED
/// IPv6 loopback (`::ffff:127.0.0.1`) as loopback: on a `::` dual-stack bind the OS
/// reports an IPv4 loopback client in that mapped form, which `Ipv6Addr::is_loopback`
/// (true only for `::1`) would otherwise miss (#1664b). Shared so the origin classifier
/// (`server::read_origin_for`) and the `DIG_NODE_HOST` enforcement below apply ONE rule,
/// and so #1646 can reuse it rather than re-deriving the mapped-loopback case.
pub fn is_loopback_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        // `::1` directly, or an IPv4-mapped loopback like `::ffff:127.0.0.1`.
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Enforce the loopback-only invariant on a `DIG_NODE_HOST` override (#1662):
/// returns `Some(message)` when the override MUST be refused — a non-loopback bind
/// address without the explicit `DIG_NODE_ALLOW_REMOTE=1` escape hatch — and `None`
/// when the bind is permitted (no override, a loopback override, or `allow_remote`).
///
/// This is what makes the ~25 "loopback-only / never peer-reachable" invariants across
/// the service TRUE rather than merely asserted: the local RPC/content API is either
/// bound to loopback, or the operator has DELIBERATELY opted into a remote bind. The
/// caller (`server::serve_with_shutdown`) fails CLOSED on `Some` — a bad override is a
/// hard startup error, never a silent LAN exposure. PURE so the policy is unit-testable.
///
/// This governs ONLY the local RPC/content bind ([`Config::bind_addr`]); the peer P2P
/// wire (mTLS `:9444`, in dig-node-core) and the loopback wallet mTLS `:9776` listener
/// bind independently, so enforcing loopback here never affects peer connectivity.
pub fn host_override_refusal(host: Option<IpAddr>, allow_remote: bool) -> Option<String> {
    match host {
        Some(ip) if !is_loopback_addr(&ip) && !allow_remote => Some(format!(
            "refusing to bind the local API to a non-loopback address ({ip}); this exposes the \
             node's RPC/content API to the network. Set DIG_NODE_ALLOW_REMOTE=1 to override."
        )),
        _ => None,
    }
}

/// Whether a request `Host` header is allowed (#91, #288). The node is
/// loopback-only and answers to the canonical local names — bare `dig.local`,
/// `localhost`, the loopback IPs `127.0.0.1`/`127.0.0.2`, and the IPv6 loopback
/// `::1` (bracketed `[::1]`/`[::1]:<port>` per RFC 7230's mandatory bracketing for
/// an IPv6-literal Host, or bare `::1` for a non-browser client that omits them) —
/// with or without a `:port` suffix; a missing Host is allowed (HTTP/1.0 / health
/// probes). Any OTHER host (e.g. a public domain pointed at the machine, the
/// classic DNS-rebinding vector) is rejected, so even though the listeners are
/// loopback-only (enforced — a non-loopback `DIG_NODE_HOST` is refused unless
/// `DIG_NODE_ALLOW_REMOTE=1`, [`host_override_refusal`], #1662) the node never serves
/// a foreign-named request. PURE: takes the
/// raw header value, returns the decision.
pub fn host_is_allowed(host_header: Option<&str>) -> bool {
    // No Host header at all (HTTP/1.0, some probes) → allow: it cannot be a
    // rebinding attack (there is no attacker-chosen name) and the loopback bind
    // already constrains reachability.
    let Some(raw) = host_header else {
        return true;
    };
    let host = raw.trim();
    if host.is_empty() {
        return true;
    }

    // IPv6-literal forms (#288): `[::1]` / `[::1]:<port>` (bracketed, the ONLY
    // legal way to carry an IPv6 literal in a Host header per RFC 7230 — the
    // brackets disambiguate the address's own colons from the port separator), or
    // bare `::1` for a non-browser client that skips the brackets. Checked BEFORE
    // the generic `:port`-strip below, because naively splitting an IPv6 literal
    // on its LAST `:` would still work for these two specific shapes, but bracket
    // handling makes the intent explicit and rejects malformed bracket forms.
    if let Some(inner) = host.strip_prefix('[') {
        return match inner.strip_suffix(']') {
            Some(addr) => addr == "::1",
            None => inner
                .rsplit_once("]:")
                .is_some_and(|(addr, _port)| addr == "::1"),
        };
    }
    if host == "::1" {
        return true;
    }

    // Strip a trailing `:port` (IPv4 / hostname forms only). `dig.local:80`,
    // `localhost:9778`, `127.0.0.1` all reduce to their hostname for the
    // allowlist check.
    let name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    matches!(
        name,
        DIG_LOCAL_HOST | "localhost" | "127.0.0.1" | "127.0.0.2"
    )
}

/// Whether `s` carries any character that must never survive into a value this node persists or
/// bakes into a service unit file: a C0/C1 control character, which includes newline, carriage
/// return and NUL.
///
/// Stated over the CLASS of control characters rather than over the specific line terminators that
/// make systemd unit-file injection work (#526/B2) — a check justified by one attacker trick is
/// bypassed by the next variant, and no legitimate URL or filesystem path needs one.
pub fn contains_control_character(s: &str) -> bool {
    s.chars().any(char::is_control)
}

/// Normalise an upstream URL: trim, strip trailing slashes, and default a bare
/// host to `https://`. Pure so the precedence/normalisation is unit-testable.
pub fn normalize_upstream(raw: &str) -> String {
    let t = raw.trim().trim_end_matches('/');
    // A control character can never be part of a URL, and an upstream is baked verbatim into a line
    // of a privileged systemd unit file at install time (#526/B2), so reject the whole value here at
    // the SOURCE rather than let it persist and be caught later: an embedded newline would let a
    // stored config append directives to a root-owned unit. Empty ⇒ "use the default".
    if t.is_empty() || contains_control_character(t) {
        return String::new();
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{t}")
    }
}

/// Split a normalised upstream into `(host, port)`, defaulting the port from the scheme.
///
/// Pure, and deliberately tolerant: anything it cannot parse yields `None`, which the caller
/// treats as "not provably self" rather than as an error. The self-reference check this feeds is a
/// safety net over an operator's value, not a URL validator.
fn upstream_host_port(upstream: &str) -> Option<(String, u16)> {
    let (scheme_port, rest) = if let Some(r) = upstream.strip_prefix("https://") {
        (443u16, r)
    } else {
        (80u16, upstream.strip_prefix("http://")?)
    };
    // Drop any path/query so `http://127.0.0.1:9778/rpc` compares as `127.0.0.1:9778`.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Strip userinfo, which is part of the authority but not the host.
    let authority = authority.rsplit('@').next().unwrap_or(authority);

    // An IPv6 literal is bracketed, and its colons must not be read as a port separator.
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let (host, tail) = after_bracket.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => scheme_port,
        };
        return Some((host.to_ascii_lowercase(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, p)) => Some((host.to_ascii_lowercase(), p.parse().ok()?)),
        None => Some((authority.to_ascii_lowercase(), scheme_port)),
    }
}

/// Whether `upstream` names THIS node — a node configured to relay to itself (#1997).
///
/// PURE, no DNS, no I/O: it recognises only the shapes that are self-evidently this process — a
/// loopback host on the port this node serves, or the `dig.local` alias on its privileged port.
/// Both are exactly what an operator produces by copying the node's own address into the upstream
/// slot.
///
/// # What this deliberately does NOT catch
///
/// A *public* name that resolves back to this host — `https://rpc.dig.net` configured on the box
/// that answers `rpc.dig.net` — is invisible here, because deciding it needs DNS plus knowledge of
/// which public names terminate at this process, and a resolver answer is neither stable nor
/// trustworthy enough to gate startup on. That case is caught at runtime instead, by the
/// relay-loop probe in [`crate::server`], which detects the loop by observing a request come back
/// rather than by predicting that it will. The two are complementary and neither replaces the
/// other: this one is instant and offline, that one is topology-aware.
pub fn is_self_upstream(upstream: &str, serving_port: u16) -> bool {
    let Some((host, port)) = upstream_host_port(upstream) else {
        return false;
    };

    // Every name that reaches THIS process: the loopback family, plus `dig.local`, which the
    // installer's hosts entry points at the loopback alias 127.0.0.2 (#91).
    let names_this_host = host == "dig.local"
        || matches!(host.as_str(), "localhost" | "::1")
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
        || host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback());

    // Stated over the CLASS of ports this node listens on, not one member of it. The node binds
    // FOUR: the configurable localhost port, `dig.local` plaintext :80, and the `https://dig.local`
    // TLS pair on :443 (127.0.0.2 and [::1], #624). Naming only :80 here left the likeliest
    // hand-typed self value — `DIG_RPC_UPSTREAM=dig.local`, which `normalize_upstream` turns into
    // `https://dig.local`, i.e. port 443 — unrefused. A guard justified by one spelling is bypassed
    // by the next spelling of the same thing.
    let own_ports = [serving_port, DIG_LOCAL_PORT, DIG_LOCAL_HTTPS_PORT];

    names_this_host && own_ports.contains(&port)
}

/// Resolve the explicit cache dir from a raw `DIG_NODE_CACHE` value: a non-blank
/// value is honoured (trimmed); a missing or blank/whitespace value is `None`,
/// meaning "use dig-node's shared canonical default". PURE so the
/// honour-vs-default policy is unit-testable without touching process env.
pub fn resolve_cache_dir(raw: Option<String>) -> Option<String> {
    cache_dir_env_value(raw.as_deref())
}

/// The value to write to `DIG_NODE_CACHE`, given the config's `cache_dir`: a
/// trimmed non-empty path, or `None` (don't set the env var → shared default).
/// PURE — the single place the "only set when explicit" rule lives, shared by
/// [`Config::from_env`] and [`Config::apply_to_env`].
pub fn cache_dir_env_value(cache_dir: Option<&str>) -> Option<String> {
    cache_dir
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_upstream_trims_and_strips_trailing_slash() {
        assert_eq!(
            normalize_upstream("https://rpc.dig.net/"),
            "https://rpc.dig.net"
        );
        assert_eq!(
            normalize_upstream("  https://rpc.dig.net///  "),
            "https://rpc.dig.net"
        );
    }

    #[test]
    fn normalize_upstream_defaults_scheme_to_https() {
        assert_eq!(normalize_upstream("rpc.dig.net"), "https://rpc.dig.net");
        assert_eq!(
            normalize_upstream("http://127.0.0.1:9000"),
            "http://127.0.0.1:9000"
        );
    }

    /// **Proves:** a dig-node ships with NO upstream, so an unimplemented method is answered
    /// locally instead of being forwarded to a third party (#1997).
    /// **Catches:** anyone reinstating a well-known host here, which is the exact change that
    /// made `rpc.dig.net` structurally special and then made it relay to itself.
    #[test]
    fn there_is_no_default_upstream() {
        assert_eq!(DEFAULT_UPSTREAM, "");
        assert_eq!(Config::default().upstream, "");
    }

    /// **Proves:** every self-evidently-self shape is recognised — the node's own port on each
    /// loopback spelling, and the `dig.local` alias.
    /// **Catches:** a parser that reads `[::1]:9778`'s host as `[` or splits an IPv6 literal on
    /// its own colons, which would let the most likely hand-typed self value through.
    #[test]
    fn an_upstream_naming_this_node_is_self() {
        for u in [
            "http://127.0.0.1:9778",
            "http://localhost:9778",
            "http://[::1]:9778",
            "https://127.0.0.1:9778",
            "http://127.0.0.2:9778",
            "http://127.0.0.1:9778/",
            "http://127.0.0.1:9778/rpc?x=1",
            "http://dig.local",
            "http://dig.local:80",
            // The likeliest hand-typed self value of all: a bare host, which normalize_upstream
            // turns into `https://dig.local` — port 443, the TLS dig.local listener (#624).
            "dig.local",
            "https://dig.local",
            "https://dig.local:443",
            // The TLS pair's own addresses, both families.
            "https://127.0.0.2",
            "https://[::1]",
            // The plaintext dig.local alias reached by IP rather than by name.
            "http://127.0.0.2",
            "http://[::1]:80",
        ] {
            assert!(
                is_self_upstream(&normalize_upstream(u), 9778),
                "{u} names this node"
            );
        }
    }

    /// **Proves:** the check stays narrow — a different node on loopback, a different port, and
    /// any remote host are all legitimate upstreams.
    /// **Catches:** an over-broad rule that disables passthrough for the developer running two
    /// nodes side by side, which would make the safety net indistinguishable from a bug.
    #[test]
    fn an_upstream_naming_another_node_is_not_self() {
        for u in [
            "http://127.0.0.1:9999",
            "http://localhost:8080",
            "https://rpc.dig.net",
            "https://some-peer.example:9778",
            // A second node on loopback at a port this one does not bind: a real, supported
            // development setup. Refusing it would make the guard indistinguishable from a bug.
            "http://127.0.0.1:19778",
            "http://[::1]:19778",
            // A host that merely CONTAINS a self-ish name is not this node.
            "https://dig.local.example.com",
            "https://not-dig.local:443",
            "not a url",
            "",
        ] {
            assert!(
                !is_self_upstream(&normalize_upstream(u), 9778),
                "{u} does not name this node"
            );
        }
    }

    /// **Proves:** the serving port is what decides it, so a node on a non-default port is
    /// protected too.
    /// **Catches:** hardcoding 9778 in the check instead of reading the resolved port.
    #[test]
    fn self_detection_follows_the_serving_port() {
        assert!(is_self_upstream("http://127.0.0.1:1234", 1234));
        assert!(!is_self_upstream("http://127.0.0.1:1234", 9778));
    }

    #[test]
    fn normalize_upstream_empty_stays_empty() {
        assert_eq!(normalize_upstream(""), "");
        assert_eq!(normalize_upstream("   "), "");
        assert_eq!(normalize_upstream("///"), "");
    }

    #[test]
    fn default_config_is_loopback_9778() {
        let c = Config::default();
        assert_eq!(c.port, DEFAULT_PORT);
        // #132: the default localhost port is the uncommon high port 9778 (the
        // dig-wallet 9777 sibling), NOT the collision-prone 8080.
        assert_eq!(DEFAULT_PORT, 9778);
        assert_eq!(
            c.bind_addr(),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9778)
        );
        assert_eq!(c.upstream, DEFAULT_UPSTREAM);
    }

    // ----- #288: dual-stack loopback bind (127.0.0.1 AND [::1]) ----------------

    #[test]
    fn default_config_binds_both_loopback_families() {
        // No DIG_NODE_HOST override → the default is dual-stack: the always-on
        // IPv4 loopback AND the additional (best-effort) IPv6 loopback, same port.
        let c = Config::default();
        assert_eq!(c.host, None);
        assert_eq!(
            c.bind_addr(),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9778)
        );
        assert_eq!(
            c.bind_addr_v6(),
            Some(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 9778))
        );
    }

    #[test]
    fn explicit_host_override_replaces_rather_than_extends_the_default_bind() {
        // An explicit DIG_NODE_HOST fully replaces the dual-stack default with
        // exactly that one address — it does not ALSO open [::1].
        let c = Config {
            host: Some(std::net::Ipv4Addr::new(10, 0, 0, 5).into()),
            ..Config::default()
        };
        assert_eq!(
            c.bind_addr(),
            SocketAddr::new(Ipv4Addr::new(10, 0, 0, 5).into(), 9778)
        );
        assert_eq!(c.bind_addr_v6(), None);
    }

    // ----- #1682: an IPv6 authority is never rendered by text concatenation -----

    /// Every bind address this config can produce, as the string the node actually binds,
    /// paired with a label naming the accessor it came from.
    ///
    /// Collected through `to_string()` deliberately: that is the exact rendering the bind
    /// path and every operator-facing URL consume, so a test that goes through it cannot
    /// pass by inspecting typed parts the render then discards.
    fn rendered_bind_addresses(c: &Config) -> Vec<(&'static str, String)> {
        let mut out = vec![("bind_addr", c.bind_addr().to_string())];
        if let Some(v6) = c.bind_addr_v6() {
            out.push(("bind_addr_v6", v6.to_string()));
        }
        if let Some(dl) = c.dig_local_addr() {
            out.push(("dig_local_addr", dl.to_string()));
        }
        if let Some(dl) = c.dig_local_https_addr() {
            out.push(("dig_local_https_addr", dl.to_string()));
        }
        if let Some(dl) = c.dig_local_https_addr_v6() {
            out.push(("dig_local_https_addr_v6", dl.to_string()));
        }
        out
    }

    /// **Proves:** a literal IPv6 `DIG_NODE_HOST` produces a bind address that PARSES —
    /// asserted against the exact [`SocketAddr`] expected, not against a substring.
    ///
    /// **Catches:** the #1682 defect exactly. `bind_addr` rendered host and port by text, so
    /// `DIG_NODE_HOST=::1` yielded the unbracketed `::1:9778`, which is not a socket address in
    /// the grammar — and the bind failure on THIS address is documented FATAL. So configuring
    /// the family §5.2 makes preferred took the node down.
    ///
    /// Two hosts, both real: the loopback an operator on Windows actually reaches the node by,
    /// and a full-form global-unicast address whose own embedded colons are what make the
    /// missing brackets ambiguous rather than merely ugly.
    #[test]
    fn an_ipv6_host_override_binds_a_parseable_address() {
        for (host, expected) in [
            (
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                "[::1]:9778".parse::<SocketAddr>().expect("v6 loopback"),
            ),
            (
                "2001:db8::1".parse::<IpAddr>().expect("v6 global literal"),
                "[2001:db8::1]:9778"
                    .parse::<SocketAddr>()
                    .expect("v6 global"),
            ),
        ] {
            let c = Config {
                host: Some(host),
                ..Config::default()
            };
            let rendered = c.bind_addr().to_string();
            let parsed = rendered.parse::<SocketAddr>().unwrap_or_else(|e| {
                panic!("DIG_NODE_HOST={host} renders {rendered:?}, which does not parse: {e}")
            });
            assert_eq!(parsed, expected);
        }
    }

    /// **Proves:** EVERY address accessor renders a parseable authority under an IPv6 host —
    /// not only the one accessor #1682 named.
    ///
    /// **Catches:** a fix applied at the single site that was reported while a sibling accessor
    /// keeps concatenating. The set is enumerated from the config rather than listed per test,
    /// so a NEW accessor is covered the moment it is added to `rendered_bind_addresses`.
    #[test]
    fn every_bind_accessor_renders_a_parseable_authority_for_an_ipv6_host() {
        for host in [
            None,
            Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ] {
            let c = Config {
                host,
                ..Config::default()
            };
            for (label, rendered) in rendered_bind_addresses(&c) {
                assert!(
                    rendered.parse::<SocketAddr>().is_ok(),
                    "host={host:?}: {label} rendered {rendered:?}, which is not a socket address"
                );
            }
        }
    }

    #[test]
    fn parse_host_override_parses_a_valid_ip_literal() {
        assert_eq!(
            parse_host_override(Some("127.0.0.1".to_string())),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            parse_host_override(Some(" ::1 ".to_string())),
            Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn parse_host_override_is_none_when_unset_blank_or_unparsable() {
        assert_eq!(parse_host_override(None), None);
        assert_eq!(parse_host_override(Some(String::new())), None);
        assert_eq!(parse_host_override(Some("   ".to_string())), None);
        assert_eq!(parse_host_override(Some("not-an-ip".to_string())), None);
    }

    #[test]
    fn default_config_has_no_explicit_cache_dir() {
        // Omitting DIG_NODE_CACHE means "use dig-node's shared canonical default"
        // (the SAME dir the DIG Browser's in-process node uses) — so the resolved
        // config carries None, never a hard-coded path that would diverge from it.
        assert_eq!(Config::default().cache_dir, None);
    }

    #[test]
    fn apply_to_env_does_not_set_cache_when_unset() {
        // When the operator did NOT set DIG_NODE_CACHE, this service must NOT write
        // it — leaving dig-node free to resolve its shared canonical default. (We
        // assert via the pure helper so the test never mutates process-global env,
        // which would race the concurrent server tests.)
        let none: Option<&str> = None;
        assert_eq!(cache_dir_env_value(none), None);
        assert_eq!(cache_dir_env_value(Some("   ")), None);
    }

    #[test]
    fn apply_to_env_sets_explicit_cache_dir() {
        // An explicit DIG_NODE_CACHE is honoured: it is the value this service
        // re-applies to the read path's env (so a service install records it, and the
        // node + this service's /health agree on the same shared dir).
        assert_eq!(
            cache_dir_env_value(Some("D:/dig/shared-cache")),
            Some("D:/dig/shared-cache".to_string())
        );
    }

    #[test]
    fn from_env_reads_explicit_cache_dir() {
        // Drive the same resolution the real Config::from_env runs, but on an
        // explicit value (pure helper) so we don't touch process env.
        assert_eq!(
            resolve_cache_dir(Some("/var/lib/dignode/cache".to_string())),
            Some("/var/lib/dignode/cache".to_string())
        );
        assert_eq!(resolve_cache_dir(Some("   ".to_string())), None);
        assert_eq!(resolve_cache_dir(None), None);
    }

    // ----- #91: the dig.local listener flag + addressing -----------------------

    #[test]
    fn dig_local_is_on_by_default() {
        // Auto-attempt with graceful fallback: a default Config wants the
        // bare-dig.local listener, addressed 127.0.0.2:80.
        let c = Config::default();
        assert!(c.dig_local);
        assert_eq!(
            c.dig_local_addr(),
            Some(SocketAddr::new(DIG_LOCAL_IP.into(), 80))
        );
    }

    #[test]
    fn dig_local_addr_is_none_when_disabled() {
        let c = Config {
            dig_local: false,
            ..Config::default()
        };
        assert_eq!(c.dig_local_addr(), None);
    }

    #[test]
    fn dig_local_https_addr_is_443_when_enabled() {
        // The bare `https://dig.local` surface (#624) shares the dig_local toggle and
        // binds 127.0.0.2:443, with the IPv6 loopback sibling on [::1]:443 (§5.2).
        let c = Config::default();
        assert_eq!(
            c.dig_local_https_addr(),
            Some(SocketAddr::new(DIG_LOCAL_IP.into(), 443))
        );
        assert_eq!(
            c.dig_local_https_addr_v6(),
            Some(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443))
        );
    }

    #[test]
    fn dig_local_https_addr_is_none_when_disabled() {
        let c = Config {
            dig_local: false,
            ..Config::default()
        };
        assert_eq!(c.dig_local_https_addr(), None);
        assert_eq!(c.dig_local_https_addr_v6(), None);
    }

    #[test]
    fn parse_dig_local_flag_honours_truthy_and_falsy_values() {
        // Falsy turns it off.
        for off in ["0", "false", "FALSE", "no", " off ", "Off"] {
            assert!(
                !parse_dig_local_flag(Some(off.to_string())),
                "{off:?} should disable dig.local"
            );
        }
        // Truthy keeps it on.
        for on in ["1", "true", "YES", "on", " On "] {
            assert!(
                parse_dig_local_flag(Some(on.to_string())),
                "{on:?} should enable dig.local"
            );
        }
        // Unset / blank / unrecognised → default ON (auto-attempt + fallback).
        assert!(parse_dig_local_flag(None));
        assert!(parse_dig_local_flag(Some(String::new())));
        assert!(parse_dig_local_flag(Some("maybe".to_string())));
    }

    #[test]
    fn parse_live_broadcast_flag_is_off_by_default_and_only_truthy_enables() {
        // Truthy enables real mainnet broadcast.
        for on in ["1", "true", "YES", "on", " On "] {
            assert!(
                parse_live_broadcast_flag(Some(on.to_string())),
                "{on:?} should enable live broadcast"
            );
        }
        // Everything else — unset, blank, falsy, or unrecognised — is the money-safe default OFF.
        assert!(!parse_live_broadcast_flag(None), "unset ⇒ OFF (money-safe)");
        assert!(!parse_live_broadcast_flag(Some(String::new())));
        assert!(!parse_live_broadcast_flag(Some("maybe".to_string())));
        for off in ["0", "false", "no", "off"] {
            assert!(!parse_live_broadcast_flag(Some(off.to_string())));
        }
        // And the resolved Config default matches (opt-in only).
        assert!(!Config::default().enable_live_broadcast);
    }

    #[test]
    fn host_allowlist_accepts_the_canonical_local_names() {
        // The four canonical names, bare and with a :port suffix, plus a missing
        // Host (probes / HTTP/1.0) are all allowed.
        for ok in [
            "dig.local",
            "dig.local:80",
            "localhost",
            "localhost:9778",
            "127.0.0.1",
            "127.0.0.1:9778",
            "127.0.0.2",
            "127.0.0.2:80",
            "  dig.local  ",
        ] {
            assert!(host_is_allowed(Some(ok)), "{ok:?} must be allowed");
        }
        assert!(host_is_allowed(None), "a missing Host must be allowed");
        assert!(host_is_allowed(Some("")), "an empty Host must be allowed");
    }

    #[test]
    fn host_allowlist_accepts_ipv6_loopback_forms() {
        // #288: a `localhost` client whose resolver returns `::1` first (Windows
        // default) sends a bracketed IPv6-literal Host; a non-browser client may
        // send it bare. All must be allowed the same as the IPv4 loopback forms.
        for ok in ["::1", "[::1]", "[::1]:9778", "[::1]:80"] {
            assert!(host_is_allowed(Some(ok)), "{ok:?} must be allowed");
        }
    }

    #[test]
    fn host_allowlist_rejects_foreign_hosts() {
        // Anything not on the loopback allowlist (the DNS-rebinding vector) is
        // rejected even though the listeners are loopback-only.
        for bad in [
            "evil.example.com",
            "example.com:80",
            "dig.local.evil.com",
            "169.254.1.1",
            "0.0.0.0",
            "attacker",
        ] {
            assert!(!host_is_allowed(Some(bad)), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn host_allowlist_rejects_non_loopback_ipv6_and_malformed_brackets() {
        // A non-loopback IPv6 literal (the rebinding vector, ipv6 flavor) and
        // malformed bracket forms must NOT be allowed.
        for bad in ["[::2]", "[fe80::1]", "[::1", "[]", "[::1]evil"] {
            assert!(!host_is_allowed(Some(bad)), "{bad:?} must be rejected");
        }
    }

    // ----- #1662: enforce a loopback-only DIG_NODE_HOST unless DIG_NODE_ALLOW_REMOTE ----

    #[test]
    fn allow_remote_flag_is_off_by_default_and_only_truthy_enables() {
        for on in ["1", "true", "YES", "on", " On "] {
            assert!(
                parse_allow_remote_flag(Some(on.to_string())),
                "{on:?} should permit a non-loopback bind"
            );
        }
        // Unset, blank, falsy, or unrecognised → the security-safe default OFF.
        assert!(
            !parse_allow_remote_flag(None),
            "unset ⇒ OFF (loopback-only)"
        );
        assert!(!parse_allow_remote_flag(Some(String::new())));
        assert!(!parse_allow_remote_flag(Some("maybe".to_string())));
        for off in ["0", "false", "no", "off"] {
            assert!(!parse_allow_remote_flag(Some(off.to_string())));
        }
        // The resolved Config default is loopback-only (opt-in remote only).
        assert!(!Config::default().allow_remote);
    }

    #[test]
    fn is_loopback_addr_covers_v4_v6_and_ipv4_mapped_loopback() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        // Native loopback, both families.
        assert!(is_loopback_addr(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_loopback_addr(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
        assert!(is_loopback_addr(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // #1664b: the IPv4-mapped IPv6 loopback (`::ffff:127.0.0.1`) seen on a `::`
        // dual-stack bind is loopback too, even though `Ipv6Addr::is_loopback` misses it.
        assert!(is_loopback_addr(&IpAddr::V6(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped()
        )));
        // Non-loopback of either family is not loopback.
        assert!(!is_loopback_addr(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(!is_loopback_addr(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
        assert!(!is_loopback_addr(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        // An IPv4-mapped NON-loopback stays non-loopback.
        assert!(!is_loopback_addr(&IpAddr::V6(
            Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped()
        )));
    }

    #[test]
    fn non_loopback_host_override_is_refused_without_the_flag() {
        // #1662: binding the local API to a non-loopback address without the explicit
        // escape hatch is a hard configuration error (fail-closed at startup).
        let host = Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        let refusal = host_override_refusal(host, /* allow_remote */ false);
        assert!(
            refusal.is_some(),
            "0.0.0.0 without DIG_NODE_ALLOW_REMOTE must be refused"
        );
        assert!(
            refusal.unwrap().contains("DIG_NODE_ALLOW_REMOTE"),
            "the message must name the escape hatch"
        );
        // A LAN address is refused the same way.
        assert!(
            host_override_refusal(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))), false).is_some()
        );
    }

    #[test]
    fn non_loopback_host_override_is_accepted_with_the_flag() {
        // #1662: the explicit DIG_NODE_ALLOW_REMOTE=1 escape hatch permits a
        // deliberate non-loopback bind (e.g. a remote-API test rig, #1062).
        let host = Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(host_override_refusal(host, /* allow_remote */ true).is_none());
    }

    #[test]
    fn loopback_host_override_is_accepted_without_the_flag() {
        use std::net::Ipv6Addr;
        // #1662: loopback overrides (IPv4 AND IPv6) never need the flag — they are
        // not peer-reachable, so they preserve the loopback-only invariant.
        for host in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert!(
                host_override_refusal(Some(host), false).is_none(),
                "{host:?} is loopback and must be accepted without the flag"
            );
        }
        // And the no-override default (dual-stack loopback) is always accepted.
        assert!(host_override_refusal(None, false).is_none());
    }
}
