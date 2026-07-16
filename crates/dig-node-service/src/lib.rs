//! dig-node-service — the localhost DIG node OS-service shell (binary `dig-node`).
//!
//! This crate is the SERVICE HOST around the canonical [`dig_node_core`] node library (a
//! first-party sibling crate in this repo): it adds an axum HTTP transport, the
//! control-plane auth gate, the CLI, and OS-service registration, and delegates every
//! read request to the node's [`dig_node_core::handle_rpc`]. The DIG Chrome extension
//! resolves `chia://` (DIG) URLs by calling a DIG RPC for encrypted, merkle-proven
//! content, then verifying + decrypting it **in the extension**. By default it talks
//! to `rpc.dig.net`; pointing its `server.host` at this node makes that RPC **local**.
//!
//! Because both this OS-service shell AND the DIG Browser's in-process shell
//! ([`dig_runtime`](https://github.com/DIG-Network/dig-node)) drive the SAME
//! [`dig_node_core`] library, the wire contract is byte-identical to rpc.dig.net
//! (ciphertext + inclusion proof + chunk lengths), with the bonus that any `.dig`
//! store the node has cached is served without leaving the machine.
//!
//! Why a single Rust binary: no runtime dependency and it installs cleanly as a
//! Windows/Linux/macOS service.
//!
//! Layout:
//! - [`config`] — env-driven [`Config`] (port/host/upstream).
//! - [`meta`] — the self-describing discovery surface: version/build info, the
//!   JSON-RPC method catalogue, the stable error-code catalogue, and the OpenRPC +
//!   `/.well-known/dig-node.json` documents.
//! - [`cli`] — the `--json` envelopes + the differentiated exit-code table.
//! - [`rpc`] — pure JSON-RPC routing + request normalisation (the testable core).
//! - [`control`] — the CONTROL/admin RPC surface (`control.*`): manage hosted
//!   stores, cache, §21 sync, config — loopback-only + local-token gated.
//! - [`server`] — the axum HTTP server (`/health`, `/version`, `/openrpc.json`,
//!   `/.well-known/dig-node.json`, CORS, `POST /` → read RPC + the control plane).
//! - [`service`] — OS-service install/uninstall/start/stop/status.

pub mod cli;
pub mod config;
/// Pure HTTP helpers for the local plaintext content-serve surface (#289): `/s/...` route parsing,
/// `<base>`/Referer store-root rerooting, the content-type map, the SPA-vs-asset classifier, and the
/// served-store CSP. The wiring lives in [`server`].
pub mod content;
pub mod control;
/// The shared CLI entrypoint ([`run`]) for BOTH the `dig-node` binary and its first-class
/// `dign` alias (issue #548). Both `src/main.rs` and `src/bin/dign.rs` are thin shims over
/// it, so the two binaries share ONE codepath and each reports its own invoked name.
pub mod entrypoint;
/// `dig-node ensure-hosts` (#91/#503): idempotently register the `dig.local` → `127.0.0.2` OS
/// hosts entry so `http://dig.local` resolves to the node. Invoked by the native install packages.
pub mod hosts;
pub mod meta;
/// `dig-node open <chia://… | urn:dig:chia:…>` (#389): the OS scheme-handler target the
/// installer registers for `chia://` + `urn:dig:chia:`. Strictly validates the untrusted
/// handler argument, then opens the user's default browser at the resolving URL. See [`open`].
pub mod open;
pub mod pair;
pub mod pairing;
pub mod rpc;
/// Shared OS-owner trust gate ([`security::dir_is_privileged`]): is a directory owned by a
/// privileged principal (SYSTEM/Administrators or root) and not user-writable? Used by the self-heal
/// spawn root (#565) and the TLS material root (#661) so the one Win32/unix owner check lives once.
pub mod security;
/// The always-on self-heal driver (#584 beacon re-arm + #651 ext-forcelist reconcile): a privileged
/// service periodically re-arms a drifted auto-update schedule + re-applies the extension
/// force-install policy, resolving its sibling CLIs by an absolute, non-user-writable path. See
/// [`self_heal`].
pub mod self_heal;
pub mod server;
pub mod service;
/// The machine-wide, identity-independent daemon STATE dir (#501): where the control token +
/// paired-token store live so the daemon (which may run as a service under a different OS
/// account) and the operator CLI resolve the SAME files. See [`state`].
pub mod state;
/// Local HTTPS TLS wiring for `https://dig.local` (#624): load the dig-cert leaf into a
/// reloadable rustls config (fail-soft when no CA/leaf yet) and drive dig-cert's leaf
/// renewal so the running listener hot-reloads a rotated leaf. See [`tls`].
pub mod tls;
/// The beacon (`dig-updater`) RPC proxy (#515): `control.updater.*` reads the DIG auto-update
/// beacon's world-readable status and shells its elevation-gated CLI for channel/pause/resume/
/// check-now — never a second implementation of the beacon's own trust logic. See [`updater`].
pub mod updater;
pub mod wallet_authz;

/// Windows Service Control Protocol entrypoint — only meaningful on Windows, where
/// the SCM-launched binary must speak the service protocol (see the module docs).
#[cfg(windows)]
pub mod win_service;

pub use cli::{ExitCode, Outcome};
pub use config::Config;
pub use entrypoint::run;
pub use meta::ErrorCode;
pub use server::{serve, VERSION};
