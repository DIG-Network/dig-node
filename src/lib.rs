//! dig-companion — the localhost DIG node for the DIG Chrome extension, as a
//! self-contained cross-platform Rust binary installable as an OS service.
//!
//! The DIG Chrome extension resolves `chia://` (DIG) URLs by calling a DIG RPC for
//! encrypted, merkle-proven content, then verifying + decrypting it **in the
//! extension**. By default it talks to `rpc.dig.net`; pointing its `server.host`
//! at this companion makes that RPC **local**. The companion routes every request
//! to digstore's `dig_node::handle_rpc` — the SAME local-first node the native DIG
//! Browser runs in-process — so the wire contract is byte-identical to rpc.dig.net
//! (ciphertext + inclusion proof + chunk lengths), with the bonus that any `.dig`
//! store the node has cached is served without leaving the machine.
//!
//! Why Rust, not the previous Node server: a single self-contained binary has no
//! runtime dependency and installs cleanly as a Windows/Linux/macOS service. The
//! Node v0.2 reference implementation is retained under `node/` for documentation.
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
pub mod control;
pub mod meta;
pub mod rpc;
pub mod server;
pub mod service;

/// Windows Service Control Protocol entrypoint — only meaningful on Windows, where
/// the SCM-launched binary must speak the service protocol (see the module docs).
#[cfg(windows)]
pub mod win_service;

pub use cli::{ExitCode, Outcome};
pub use config::Config;
pub use meta::ErrorCode;
pub use server::{serve, VERSION};
