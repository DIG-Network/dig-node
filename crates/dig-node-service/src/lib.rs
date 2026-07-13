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
pub mod meta;
/// `dig-node open <chia://… | urn:dig:chia:…>` (#389): the OS scheme-handler target the
/// installer registers for `chia://` + `urn:dig:chia:`. Strictly validates the untrusted
/// handler argument, then opens the user's default browser at the resolving URL. See [`open`].
pub mod open;
pub mod pair;
pub mod pairing;
pub mod rpc;
pub mod server;
pub mod service;
/// The machine-wide, identity-independent daemon STATE dir (#501): where the control token +
/// paired-token store live so the daemon (which may run as a service under a different OS
/// account) and the operator CLI resolve the SAME files. See [`state`].
pub mod state;
pub mod wallet_authz;

/// Windows Service Control Protocol entrypoint — only meaningful on Windows, where
/// the SCM-launched binary must speak the service protocol (see the module docs).
#[cfg(windows)]
pub mod win_service;

pub use cli::{ExitCode, Outcome};
pub use config::Config;
pub use meta::ErrorCode;
pub use server::{serve, VERSION};
