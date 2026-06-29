//! Runtime configuration for the companion, resolved from the environment.
//!
//! The companion's knobs mirror the Node v0.2 server's env contract so a deploy
//! that set those vars keeps working: `DIG_COMPANION_PORT` / `DIG_COMPANION_HOST`
//! pick the bind address; `DIG_RPC_UPSTREAM` picks the upstream the embedded
//! dig-node proxies blind ciphertext/proof requests to on a cache miss.
//!
//! The upstream is wired into dig-node via its own `DIG_NODE_UPSTREAM` env var
//! (see [`Config::apply_to_env`]) — dig-node reads that name internally, so the
//! companion translates its public `DIG_RPC_UPSTREAM` knob into it.
//!
//! ## Shared `.dig` cache (#96)
//!
//! `DIG_NODE_CACHE` points dig-node at the on-disk `.dig` cache. The companion
//! reads it **explicitly** ([`Config::cache_dir`]) so an operator/installer can aim
//! it at one canonical cache, and re-applies it to dig-node's environment in
//! [`Config::apply_to_env`].
//!
//! **Omitting it is the right default for sharing.** When `DIG_NODE_CACHE` is
//! unset, the companion does NOT invent a path — it leaves dig-node to resolve its
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

use std::net::{IpAddr, Ipv4Addr};

/// Default loopback bind port. The DIG Chrome extension defaults its `server.host`
/// to `localhost:80`, but port 80 needs elevation on most OSes, so the companion
/// defaults to 8080 (set the extension's server host to `localhost:8080` to match).
pub const DEFAULT_PORT: u16 = 8080;

/// Default upstream DIG RPC the embedded node proxies to on a local cache miss.
pub const DEFAULT_UPSTREAM: &str = "https://rpc.dig.net";

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

/// Resolved companion configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Bind address (always loopback by default — the companion is a localhost
    /// endpoint for a same-machine browser/extension, never a public server).
    pub host: IpAddr,
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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_PORT,
            upstream: DEFAULT_UPSTREAM.to_string(),
            cache_dir: None,
            // Auto-attempt the bare-dig.local listener by default (graceful
            // fallback if the privileged bind fails) — see the field doc + #91.
            dig_local: true,
        }
    }
}

impl Config {
    /// Resolve the config from the process environment, falling back to defaults.
    /// Mirrors the Node server's `DIG_COMPANION_PORT` / `DIG_COMPANION_HOST` /
    /// `DIG_RPC_UPSTREAM` contract.
    pub fn from_env() -> Self {
        let port = std::env::var("DIG_COMPANION_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|p| *p != 0)
            .unwrap_or(DEFAULT_PORT);

        let host = std::env::var("DIG_COMPANION_HOST")
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

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

        // DIG_NODE_CACHE is read with dig-node's OWN env var name (not a companion
        // alias) so a value the operator sets reaches the node directly and the
        // companion just makes honouring it explicit. A blank/whitespace value is
        // treated as unset → shared default (see resolve_cache_dir).
        let cache_dir = resolve_cache_dir(std::env::var("DIG_NODE_CACHE").ok());

        // The bare-dig.local listener is on by default (auto-attempt + graceful
        // fallback); DIG_NODE_DIGLOCAL=0/false/no/off turns it off entirely.
        let dig_local = parse_dig_local_flag(std::env::var("DIG_NODE_DIGLOCAL").ok());

        Config {
            host,
            port,
            upstream,
            cache_dir,
            dig_local,
        }
    }

    /// Apply this config to the environment dig-node reads at `Node::from_env()`:
    ///
    /// * `DIG_NODE_UPSTREAM` ← the companion's public `DIG_RPC_UPSTREAM` knob.
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

    /// The `host:port` socket string for the always-on localhost listener
    /// (binding / logging).
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// The `host:port` socket string for the BEST-EFFORT bare-`http://dig.local`
    /// listener (`127.0.0.2:80`), or `None` when `dig_local` is disabled (#91).
    /// `serve` tries to bind this in ADDITION to [`bind_addr`]; a failure is
    /// logged and ignored (localhost keeps serving).
    pub fn dig_local_addr(&self) -> Option<String> {
        self.dig_local
            .then(|| format!("{DIG_LOCAL_IP}:{DIG_LOCAL_PORT}"))
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

/// Whether a request `Host` header is allowed (#91). The node is loopback-only and
/// answers to the canonical local names — bare `dig.local`, `localhost`, the two
/// loopback IPs `127.0.0.1`/`127.0.0.2` — with or without a `:port` suffix; a
/// missing Host is allowed (HTTP/1.0 / health probes). Any OTHER host (e.g. a
/// public domain pointed at the machine, the classic DNS-rebinding vector) is
/// rejected, so even though the listeners are loopback-only the node never serves a
/// foreign-named request. PURE: takes the raw header value, returns the decision.
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
    // Strip a trailing `:port` (IPv4 / hostname forms only — the node binds IPv4
    // loopback, never `[::1]`). `dig.local:80`, `localhost:8080`, `127.0.0.1` all
    // reduce to their hostname for the allowlist check.
    let name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    matches!(
        name,
        DIG_LOCAL_HOST | "localhost" | "127.0.0.1" | "127.0.0.2"
    )
}

/// Normalise an upstream URL: trim, strip trailing slashes, and default a bare
/// host to `https://`. Pure so the precedence/normalisation is unit-testable.
pub fn normalize_upstream(raw: &str) -> String {
    let t = raw.trim().trim_end_matches('/');
    if t.is_empty() {
        return String::new();
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{t}")
    }
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

    #[test]
    fn normalize_upstream_empty_stays_empty() {
        assert_eq!(normalize_upstream(""), "");
        assert_eq!(normalize_upstream("   "), "");
        assert_eq!(normalize_upstream("///"), "");
    }

    #[test]
    fn default_config_is_loopback_8080() {
        let c = Config::default();
        assert_eq!(c.port, DEFAULT_PORT);
        assert_eq!(c.bind_addr(), "127.0.0.1:8080");
        assert_eq!(c.upstream, DEFAULT_UPSTREAM);
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
        // When the operator did NOT set DIG_NODE_CACHE, the companion must NOT write
        // it — leaving dig-node free to resolve its shared canonical default. (We
        // assert via the pure helper so the test never mutates process-global env,
        // which would race the concurrent server tests.)
        let none: Option<&str> = None;
        assert_eq!(cache_dir_env_value(none), None);
        assert_eq!(cache_dir_env_value(Some("   ")), None);
    }

    #[test]
    fn apply_to_env_sets_explicit_cache_dir() {
        // An explicit DIG_NODE_CACHE is honoured: it is the value the companion
        // re-applies to dig-node's env (so a service install records it, and the
        // node + the companion's /health agree on the same shared dir).
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
        assert_eq!(c.dig_local_addr().as_deref(), Some("127.0.0.2:80"));
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
    fn host_allowlist_accepts_the_canonical_local_names() {
        // The four canonical names, bare and with a :port suffix, plus a missing
        // Host (probes / HTTP/1.0) are all allowed.
        for ok in [
            "dig.local",
            "dig.local:80",
            "localhost",
            "localhost:8080",
            "127.0.0.1",
            "127.0.0.1:8080",
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
}
