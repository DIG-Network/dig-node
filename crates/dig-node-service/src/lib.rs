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
//!   stores, cache, §21 sync, config — token-gated regardless of bind
//!   (loopback-bound by default; non-loopback only with `DIG_NODE_ALLOW_REMOTE=1`).
//! - [`server`] — the axum HTTP server (`/health`, `/version`, `/openrpc.json`,
//!   `/.well-known/dig-node.json`, CORS, `POST /` → read RPC + the control plane).
//! - [`service`] — OS-service install/uninstall/start/stop/status.

pub mod cli;
/// The deterministic mirror-coin collateral model: the per-epoch record store, the local
/// safety margin, and the funding advice built on them. Every figure comes out of
/// `dig-mirror-collateral`; no formula is restated.
pub mod collateral;
/// The census runner: the chain reads that let a node record an epoch after the first, and the
/// named reasons it declines to record one. Every stop writes nothing.
pub mod collateral_census;
/// Adopting an epoch history from untrusted peers, and serving one to them: the
/// re-derivation every candidate record must survive, and the sampling plan that bounds
/// what a sample of peers is allowed to decide.
pub mod collateral_sync;
pub mod config;
/// Pure HTTP helpers for the local plaintext content-serve surface (#289): `/s/...` route parsing,
/// `<base>`/Referer store-root rerooting, the content-type map, the SPA-vs-asset classifier, and the
/// served-store CSP. The wiring lives in [`server`].
pub mod content;
pub mod control;
/// CLI parity with the node's `control.*` surface (#426): a `dig-node`/`dign` subcommand for every
/// control the extension can drive (status, config, cache, hosted stores, §21 sync, updater,
/// subscriptions), each a thin dispatch over [`control_client`] with `--json`. See [`control_cli`].
pub mod control_cli;
/// The shared OPERATOR-side loopback JSON-RPC client for the gated `control.*` surface: reads the
/// master control token read-only and POSTs a control method to the node. The ONE transport every
/// control-driving subcommand (`pair`, `control_cli`, `peers`) uses. See [`control_client`].
pub mod control_client;
/// The shared CLI entrypoint ([`run`]) for BOTH the `dig-node` binary and its first-class
/// `dign` alias (issue #548). Both `src/main.rs` and `src/bin/dign.rs` are thin shims over
/// it, so the two binaries share ONE codepath and each reports its own invoked name.
pub mod entrypoint;
/// `dig-node ensure-hosts` (#91/#503): idempotently register the `dig.local` → `127.0.0.2` OS
/// hosts entry so `http://dig.local` resolves to the node. Invoked by the native install packages.
pub mod hosts;
/// Structured logging (#553): install the shared [`dig_logging`] dual sink (rolling JSONL
/// file + human stderr) at the serve entrypoints and expose the runtime level-reload handle
/// the `control.log.setLevel` method + `logs level` verb drive. See [`logging`].
pub mod logging;
/// The DIG loopback allocation (dig_ecosystem#767): the one place that answers which loopback
/// address a DIG service binds, so no call site re-derives it and no DIG service takes
/// `127.0.0.1` from the rest of the machine. See [`loopback`].
pub mod loopback;
pub mod meta;
/// The mirror-coin lifecycle (dig-node#377, `SPEC.md` §25): presence of a `.dig` on disk drives
/// creation of an on-chain mirror coin locking the epoch's required $DIG for that
/// `(store, root, epoch)`, and its disappearance drives reclaim of the collateral. The node signs
/// those spends itself with its own operator wallet, scoped by construction. See [`mirror`].
pub mod mirror;
/// `dign network-info` (#303): this node's OWN network posture -- peer id, network + genesis,
/// advertised addresses (IPv6-first, §5.2), reachability and relay reservation. Reads the node's
/// OPEN `dig.getNetworkInfo` surface, so it needs no control token. See [`network_info`].
pub mod network_info;
/// `dig-node open <chia://… | urn:dig:chia:…>` (#389): the OS scheme-handler target the
/// installer registers for `chia://` + `urn:dig:chia:`. Strictly validates the untrusted
/// handler argument, then opens the user's default browser at the resolving URL. See [`open`].
pub mod open;
pub mod pair;
pub mod pairing;
/// `control.peers.ping` (dig_ecosystem#1985): the connection-ladder diagnostic — dial one peer a
/// tier at a time and report WHICH tier reached it. See [`peer_ping`].
pub mod peer_ping;
/// `dig-node peers` (#559): view + manage the node's peer connections from the CLI — parity with
/// the extension's peer surface, driven over the token-gated `control.*` client. See [`peers`].
pub mod peers;
/// The passthrough relay guard (#1997): whether this node relays an unimplemented method to an
/// upstream, and the bring-up probe that proves an upstream is not this node itself. See [`relay`].
pub mod relay;
pub mod rpc;
/// The offline `wallet export-seed` rescue command: a local read of this node's
/// encrypted seed file. Adds no network surface, and is removed with node-side custody.
pub mod seed_export_cli;

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
/// Stopping the service reliably (dig_ecosystem#2880): a stop signal that does not depend on
/// tokio's blocking pool, plus a bounded graceful-shutdown deadline, so a wedged internal can
/// never leave a service the OS is unable to stop. See [`service_control`].
pub mod service_control;
/// The automated-spend audit record (#376): the node's source of truth for every spend it made
/// without per-transaction user approval, and the reconciliation seam that checks that local
/// bookkeeping against the chain. See [`spend_audit`].
pub mod spend_audit;
/// `dign spends` — the LOCAL, node-free read of the audit record (#376). It reaches no node on
/// purpose: an audit surface that goes dark when the node does is not an audit surface. See
/// [`spend_audit_cli`].
pub mod spend_audit_cli;
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
/// Discovering + removing OTHER ACCOUNTS' user-scope service registrations (#526): as root, the OS
/// cannot be asked about a per-user systemd unit or a `gui/<uid>` launchd agent, so the cross-scope
/// sweep reads the filesystem per account, with a strict no-symlink discipline. See [`user_scope`].
pub mod user_scope;
pub mod wallet_authz;

/// The start-up check that a wallet seed exists, minting one if it does not (dig-node#277).
/// Never fatal, never a fallback. See [`wallet_bootstrap`].
pub mod wallet_bootstrap;

/// Latching the fact that the node's own wallet has held funds, so no surface calls a funded
/// auto-created wallet disposable (dig-node#286). See [`wallet_funded`].
pub mod wallet_funded;

/// The Sage-parity wallet mTLS listener: its bring-up and the state `dign info` reports
/// when it could not take its port (dig-node#260). See [`wallet_mtls`].
pub mod wallet_mtls;

/// Windows Service Control Protocol entrypoint — only meaningful on Windows, where
/// the SCM-launched binary must speak the service protocol (see the module docs).
#[cfg(windows)]
pub mod win_service;

pub use cli::{ExitCode, Outcome};
pub use config::Config;
pub use entrypoint::run;
pub use meta::ErrorCode;
pub use server::{serve, VERSION};
