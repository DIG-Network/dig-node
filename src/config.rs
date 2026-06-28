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

use std::net::{IpAddr, Ipv4Addr};

/// Default loopback bind port. The DIG Chrome extension defaults its `server.host`
/// to `localhost:80`, but port 80 needs elevation on most OSes, so the companion
/// defaults to 8080 (set the extension's server host to `localhost:8080` to match).
pub const DEFAULT_PORT: u16 = 8080;

/// Default upstream DIG RPC the embedded node proxies to on a local cache miss.
pub const DEFAULT_UPSTREAM: &str = "https://rpc.dig.net";

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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_PORT,
            upstream: DEFAULT_UPSTREAM.to_string(),
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

        let upstream = std::env::var("DIG_RPC_UPSTREAM")
            .ok()
            .map(|s| normalize_upstream(&s))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_UPSTREAM.to_string());

        Config {
            host,
            port,
            upstream,
        }
    }

    /// Translate the companion's public upstream knob into dig-node's own
    /// `DIG_NODE_UPSTREAM` env var, which `dig_node::Node::from_env` reads. Called
    /// before constructing the node so the proxy target is honoured. (dig-node
    /// deliberately uses a distinct name from the browser's `DIG_RPC_ENDPOINT`,
    /// which points a client AT the node; reusing that would make the node proxy
    /// to itself.)
    pub fn apply_to_env(&self) {
        std::env::set_var("DIG_NODE_UPSTREAM", &self.upstream);
    }

    /// The `host:port` socket string for binding / logging.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
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
}
