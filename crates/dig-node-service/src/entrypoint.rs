//! The shared CLI entrypoint for BOTH the `dig-node` and `dign` binaries (issue #548).
//!
//! `dign` is a FIRST-CLASS alias for `dig-node`: `dign <args>` behaves identically to
//! `dig-node <args>` (same subcommands, flags, `--json`, exit codes). Both binaries are
//! thin shims (`src/main.rs`, `src/bin/dign.rs`) over the ONE [`run`] entrypoint here,
//! so there is NO duplicated logic — and each reflects its OWN invoked name (arg0) in
//! `--help`/`--version`, making the alias a real installed binary, not a shell alias.
//!
//! Subcommands:
//!   run        Run the node in the foreground (the service entrypoint too).
//!   install    Register the node as an auto-starting OS service.
//!   uninstall  Remove the OS service.
//!   start      Start the installed service.
//!   stop       Stop the running service.
//!   status     Report whether the node is serving (probes /health).
//!
//! With no subcommand, the binary runs in the foreground (equivalent to `run`), so a
//! bare invocation just serves — the least-surprise default for a localhost endpoint.
//!
//! ## Machine-readable output (`--json`)
//!
//! Every subcommand accepts the global `--json` flag: on success it emits ONE structured
//! object to **stdout** (`{ ok:true, action, ... }`) and routes human prose to
//! **stderr**; on failure it emits `{ ok:false, error:{ code, exit_code, message, hint } }`
//! to stdout and still exits with the differentiated code. The exit-code table is
//! documented in [`crate::cli`] and the README.

use std::ffi::OsStr;
use std::path::Path;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

use crate::cli::{error_envelope, success_envelope, ExitCode, Outcome};
use crate::config::Config;
use crate::control_cli::{self, ControlAction};
use crate::open;
use crate::pair::{self, PairAction};
use crate::peers::{self, BanState, PeersAction};
use crate::{serve, service, VERSION};

#[derive(Parser)]
#[command(
    // A default only: [`run`] overrides both the displayed name and the usage `bin_name`
    // with the ACTUAL invoked binary (arg0), so `dign` reports `dign` and `dig-node`
    // reports `dig-node`. This literal is the fallback when arg0 is somehow absent.
    name = "dig-node",
    version = VERSION,
    about = "Local DIG node for the DIG Chrome extension (installable as an OS service)",
    long_about = None,
)]
struct Cli {
    /// Emit a single machine-readable JSON object to stdout (human prose → stderr).
    /// Errors are emitted as `{ok:false,error:{code,exit_code,message,hint}}`.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the node in the foreground (also the unix-service entrypoint).
    Run,
    /// Internal: the Windows-service entrypoint (speaks the SCM service protocol).
    /// Installed by `install` on Windows; not meant to be run by hand. On non-Windows
    /// it behaves like `run`.
    #[command(hide = true)]
    RunService,
    /// Register the node as an auto-starting OS service.
    Install,
    /// Remove the OS service.
    Uninstall,
    /// Start the installed service.
    Start,
    /// Stop the running service.
    Stop,
    /// Report whether the node is serving (probes /health).
    Status,
    /// Pair a browser controller (the DIG Chrome extension) with this node (#280):
    /// grant it a scoped, revocable control token after local confirmation.
    Pair {
        #[command(subcommand)]
        action: Option<PairCommand>,
    },
    /// Open a DIG link in the default browser (#389). The OS scheme-handler target the
    /// installer registers for `chia://` + `urn:dig:chia:`. Accepts ONLY those two schemes,
    /// resolves via the local node's serve URL, and never invokes a shell.
    Open {
        /// The DIG link (`chia://<storeId>[:<root>]/<path>` or `urn:dig:chia:<…>`).
        link: String,
    },
    /// Detailed node status (the gated `control.status`): version, uptime, cache, hosted-store +
    /// cached-capsule counts, §21 sync availability. Distinct from `status` (an unauthenticated
    /// liveness probe of /health); this is the token-gated rich view the extension shows.
    Info,
    /// View or change the node's config (the `control.config.*` surface the extension drives).
    Config {
        #[command(subcommand)]
        action: Option<ConfigCommand>,
    },
    /// View or manage the local content cache (the `control.cache.*` surface).
    Cache {
        #[command(subcommand)]
        action: Option<CacheCommand>,
    },
    /// List/pin/unpin hosted stores (the `control.hostedStores.*` surface).
    Stores {
        #[command(subcommand)]
        action: Option<StoresCommand>,
    },
    /// View §21 whole-store sync status or trigger a capsule sync (the `control.sync.*` surface).
    Sync {
        #[command(subcommand)]
        action: Option<SyncCommand>,
    },
    /// Drive the DIG auto-update beacon (the `control.updater.*` surface).
    Updater {
        #[command(subcommand)]
        action: Option<UpdaterCommand>,
    },
    /// List/add/remove the node's store subscriptions (the `control.subscribe`/`unsubscribe`/
    /// `listSubscriptions` surface).
    Subscriptions {
        #[command(subcommand)]
        action: Option<SubscriptionsCommand>,
    },
    /// View + manage the node's peer connections (#559) — parity with the extension's peer surface.
    /// With no sub-action, lists the live peer status (running flag, connected count, relay, and —
    /// on a newer node — the per-peer list with addresses shown IPv6-first per §5.2).
    Peers {
        #[command(subcommand)]
        action: Option<PeersCommand>,
    },
    /// Internal: idempotently register the `dig.local` → `127.0.0.2` OS hosts entry (#91/#503),
    /// so `http://dig.local` resolves to the node. Invoked by the native install packages;
    /// requires write access to the hosts file (run elevated). Not meant to be run by hand.
    #[command(hide = true)]
    EnsureHosts,
}

/// `dig-node config` sub-actions. With none, prints the current config.
#[derive(Subcommand)]
enum ConfigCommand {
    /// Print the node's effective config (addr/port, upstream, cache dir).
    Get,
    /// Persist the upstream DIG RPC override (effective on next node start).
    SetUpstream {
        /// The upstream RPC URL (blank clears the override).
        url: String,
    },
}

/// `dig-node cache` sub-actions. With none, prints the cache config.
#[derive(Subcommand)]
enum CacheCommand {
    /// Print the cache cap/used/dir/shared.
    Get,
    /// Set the on-disk cache size cap in bytes (floored at 64 MiB by the node).
    SetCap {
        /// The cap in bytes.
        bytes: u64,
    },
    /// Delete all locally cached DIG content.
    Clear,
}

/// `dig-node stores` sub-actions. With none, lists hosted stores.
#[derive(Subcommand)]
enum StoresCommand {
    /// List every hosted/pinned store + its cached capsules.
    List,
    /// Pin a store (`storeId` or `storeId:rootHash`); pre-fetches when a root is given.
    Pin {
        /// The store reference (`storeId[:rootHash]`).
        store: String,
    },
    /// Unpin a store + evict its cached capsules.
    Unpin {
        /// The store reference (`storeId[:rootHash]`).
        store: String,
    },
    /// Show one store's pin/cache status.
    Status {
        /// The store reference (`storeId[:rootHash]`).
        store: String,
    },
}

/// `dig-node sync` sub-actions. With none, prints §21 sync status.
#[derive(Subcommand)]
enum SyncCommand {
    /// Print §21 whole-store sync availability + pinned-store coverage.
    Status,
    /// Trigger a §21 sync for one capsule (`storeId:rootHash`).
    Trigger {
        /// The capsule reference (`storeId:rootHash`).
        store: String,
    },
}

/// `dig-node updater` sub-actions. With none, prints the beacon status.
#[derive(Subcommand)]
enum UpdaterCommand {
    /// Print the DIG auto-update beacon's status.
    Status,
    /// Set the beacon update channel.
    SetChannel {
        /// The channel: `nightly` or `stable`.
        channel: String,
    },
    /// Pause auto-updates, optionally until a unix-seconds deadline (else indefinitely).
    Pause {
        /// Resume automatically at this unix-seconds time (omit for an indefinite pause).
        #[arg(long)]
        until: Option<u64>,
    },
    /// Resume auto-updates.
    Resume,
    /// Check for an update now.
    CheckNow,
}

/// `dig-node subscriptions` sub-actions. With none, lists subscriptions.
#[derive(Subcommand)]
enum SubscriptionsCommand {
    /// List the node's persisted store subscriptions.
    List,
    /// Subscribe the node to a store id (chain-watch + gap-fill).
    Add {
        /// The store id (64-hex).
        store_id: String,
    },
    /// Remove a store subscription.
    Remove {
        /// The store id (64-hex).
        store_id: String,
    },
}

/// `dig-node peers` sub-actions (#559). With none, lists the live peer status.
#[derive(Subcommand)]
enum PeersCommand {
    /// List the live peer status (running flag, connected count, relay, per-peer list).
    List,
    /// Dial a peer by address or peer_id.
    Connect {
        /// The peer address or peer_id to dial.
        peer: String,
    },
    /// Drop a connected peer.
    Disconnect {
        /// The peer address or peer_id to drop.
        peer: String,
    },
    /// Block (`ban`), soft-block (`blacklist`), or clear (`none`) a peer.
    Ban {
        /// The peer address or peer_id.
        peer: String,
        /// The ban state: `ban`, `blacklist`, or `none`.
        #[arg(long)]
        state: String,
    },
    /// Set the peer-pool max-connections cap.
    PoolConfig {
        /// The maximum number of pool connections.
        #[arg(long)]
        max_connections: u32,
    },
}

/// `dig-node pair` sub-actions. With none, lists pending requests + issued tokens.
#[derive(Subcommand)]
enum PairCommand {
    /// List pending pairing requests (with codes) + issued controller tokens.
    List,
    /// Approve a pending pairing by id (mints a scoped controller token).
    Approve {
        /// The pairing_id from `dig-node pair` / the extension.
        pairing_id: String,
    },
    /// Revoke an issued controller token by id.
    Revoke {
        /// The token id from `dig-node pair`.
        token_id: String,
    },
}

impl Command {
    /// The action name used in the `--json` envelope.
    fn action(&self) -> &'static str {
        match self {
            Command::Run | Command::RunService => "run",
            Command::Install => "install",
            Command::Uninstall => "uninstall",
            Command::Start => "start",
            Command::Stop => "stop",
            Command::Status => "status",
            Command::Pair { .. } => "pair",
            Command::Open { .. } => "open",
            Command::Info => "info",
            Command::Config { .. } => "config",
            Command::Cache { .. } => "cache",
            Command::Stores { .. } => "stores",
            Command::Sync { .. } => "sync",
            Command::Updater { .. } => "updater",
            Command::Subscriptions { .. } => "subscriptions",
            Command::Peers { .. } => "peers",
            Command::EnsureHosts => "ensure-hosts",
        }
    }
}

/// The file-stem of the binary as it was invoked (arg0), e.g. `dig-node` or `dign` (the
/// issue-#548 alias). This is the program name the CLI reports in `--help`/`--version`,
/// so each binary shows its OWN name rather than a hardcoded `"dig-node"`. Falls back to
/// `"dig-node"` when arg0 is absent/empty.
fn invoked_bin_name() -> String {
    bin_name_from_arg0(std::env::args_os().next().as_deref())
}

/// Pure core of [`invoked_bin_name`]: the file-stem of an arg0 path, with the extension
/// (`.exe`) and directory prefix stripped, falling back to `"dig-node"` for an
/// absent/empty arg0. Extracted so the naming rule is unit-testable without touching the
/// process-global argv.
fn bin_name_from_arg0(arg0: Option<&OsStr>) -> String {
    arg0.map(Path::new)
        .and_then(Path::file_stem)
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "dig-node".to_string())
}

/// The shared CLI entrypoint for BOTH the `dig-node` and `dign` binaries (issue #548).
/// Kept here in the library — not duplicated in each `src/bin` shim — so the two binaries
/// are the same command surface with ONE codepath.
///
/// Parses argv with the ACTUAL invoked binary name ([`invoked_bin_name`]) as both the
/// displayed program name and the usage `bin_name`, so `dign --help` shows `dign` and
/// `dig-node --help` shows `dig-node`.
pub fn run() -> std::process::ExitCode {
    // Parse with the invoked binary's name as the program + bin name, so the alias
    // (`dign`) is first-class: its help/usage/version/errors all read `dign`, never a
    // hardcoded `dig-node`, and never the raw arg0 (which may be an absolute path).
    //
    // `Command::name` requires `Into<Str>`, which this clap only satisfies for a
    // `&'static str`; the invoked name is computed at runtime, so we leak the tiny stem
    // to obtain a `'static` reference. This is a single, process-lifetime allocation on
    // the entrypoint of a short-lived CLI — never in a loop — so it is not a meaningful
    // leak. (`bin_name` takes `Into<String>`, so it takes the owned value directly.)
    let bin = invoked_bin_name();
    let bin_static: &'static str = Box::leak(bin.clone().into_boxed_str());
    let matches = Cli::command().name(bin_static).bin_name(bin).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    let json = cli.json;
    let config = Config::from_env();
    let command = cli.command.unwrap_or(Command::Run);
    let action = command.action();

    // `run` / `run-service` serve indefinitely — they have no terminal Outcome.
    // Everything else returns an Outcome we render as JSON or prose.
    let exit = match command {
        Command::Run => render_serve(block_on_serve(config), action, json),
        Command::RunService => render_serve(run_service(config), action, json),
        Command::Install => render(service::install(&config), action, json),
        Command::Uninstall => render(service::uninstall(), action, json),
        Command::Start => render(service::start(), action, json),
        Command::Stop => render(service::stop(), action, json),
        Command::Status => render_status(service::status(&config), action, json),
        Command::Pair { action: pair_cmd } => {
            let pair_action = match pair_cmd {
                None | Some(PairCommand::List) => PairAction::List,
                Some(PairCommand::Approve { pairing_id }) => PairAction::Approve { pairing_id },
                Some(PairCommand::Revoke { token_id }) => PairAction::Revoke { token_id },
            };
            render(pair::run(&config, pair_action), action, json)
        }
        Command::Open { link } => render(open::run(&config, &link), action, json),
        Command::Info => render(control_cli::run(&config, ControlAction::Info), action, json),
        Command::Config { action: cmd } => {
            render(control_cli::run(&config, config_action(cmd)), action, json)
        }
        Command::Cache { action: cmd } => {
            render(control_cli::run(&config, cache_action(cmd)), action, json)
        }
        Command::Stores { action: cmd } => {
            render(control_cli::run(&config, stores_action(cmd)), action, json)
        }
        Command::Sync { action: cmd } => {
            render(control_cli::run(&config, sync_action(cmd)), action, json)
        }
        Command::Updater { action: cmd } => {
            render(control_cli::run(&config, updater_action(cmd)), action, json)
        }
        Command::Subscriptions { action: cmd } => render(
            control_cli::run(&config, subscriptions_action(cmd)),
            action,
            json,
        ),
        Command::Peers { action: cmd } => match peers_action(cmd) {
            Ok(a) => render(peers::run(&config, a), action, json),
            Err(e) => emit_error(&e, action, json),
        },
        Command::EnsureHosts => render(crate::hosts::run(), action, json),
    };
    std::process::ExitCode::from(exit.code())
}

/// Map the `config` subcommand to its [`ControlAction`] (no sub-action → print the config).
fn config_action(cmd: Option<ConfigCommand>) -> ControlAction {
    match cmd {
        None | Some(ConfigCommand::Get) => ControlAction::ConfigGet,
        Some(ConfigCommand::SetUpstream { url }) => ControlAction::ConfigSetUpstream { url },
    }
}

/// Map the `cache` subcommand to its [`ControlAction`] (no sub-action → print the cache config).
fn cache_action(cmd: Option<CacheCommand>) -> ControlAction {
    match cmd {
        None | Some(CacheCommand::Get) => ControlAction::CacheGet,
        Some(CacheCommand::SetCap { bytes }) => ControlAction::CacheSetCap { bytes },
        Some(CacheCommand::Clear) => ControlAction::CacheClear,
    }
}

/// Map the `stores` subcommand to its [`ControlAction`] (no sub-action → list hosted stores).
fn stores_action(cmd: Option<StoresCommand>) -> ControlAction {
    match cmd {
        None | Some(StoresCommand::List) => ControlAction::StoresList,
        Some(StoresCommand::Pin { store }) => ControlAction::StoresPin { store },
        Some(StoresCommand::Unpin { store }) => ControlAction::StoresUnpin { store },
        Some(StoresCommand::Status { store }) => ControlAction::StoresStatus { store },
    }
}

/// Map the `sync` subcommand to its [`ControlAction`] (no sub-action → print §21 sync status).
fn sync_action(cmd: Option<SyncCommand>) -> ControlAction {
    match cmd {
        None | Some(SyncCommand::Status) => ControlAction::SyncStatus,
        Some(SyncCommand::Trigger { store }) => ControlAction::SyncTrigger { store },
    }
}

/// Map the `updater` subcommand to its [`ControlAction`] (no sub-action → print beacon status).
fn updater_action(cmd: Option<UpdaterCommand>) -> ControlAction {
    match cmd {
        None | Some(UpdaterCommand::Status) => ControlAction::UpdaterStatus,
        Some(UpdaterCommand::SetChannel { channel }) => {
            ControlAction::UpdaterSetChannel { channel }
        }
        Some(UpdaterCommand::Pause { until }) => ControlAction::UpdaterPause { until },
        Some(UpdaterCommand::Resume) => ControlAction::UpdaterResume,
        Some(UpdaterCommand::CheckNow) => ControlAction::UpdaterCheckNow,
    }
}

/// Map the `subscriptions` subcommand to its [`ControlAction`] (no sub-action → list them).
fn subscriptions_action(cmd: Option<SubscriptionsCommand>) -> ControlAction {
    match cmd {
        None | Some(SubscriptionsCommand::List) => ControlAction::SubsList,
        Some(SubscriptionsCommand::Add { store_id }) => ControlAction::SubsAdd { store_id },
        Some(SubscriptionsCommand::Remove { store_id }) => ControlAction::SubsRemove { store_id },
    }
}

/// Map the `peers` subcommand to its [`PeersAction`] (no sub-action → list the peer status).
/// The only fallible mapping: a bad `--state` on `ban` becomes a USAGE `io::Error`.
fn peers_action(cmd: Option<PeersCommand>) -> std::io::Result<PeersAction> {
    Ok(match cmd {
        None | Some(PeersCommand::List) => PeersAction::List,
        Some(PeersCommand::Connect { peer }) => PeersAction::Connect { peer },
        Some(PeersCommand::Disconnect { peer }) => PeersAction::Disconnect { peer },
        Some(PeersCommand::Ban { peer, state }) => {
            let state = BanState::parse(&state)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            PeersAction::SetBan { peer, state }
        }
        Some(PeersCommand::PoolConfig { max_connections }) => {
            PeersAction::SetPoolConfig { max_connections }
        }
    })
}

/// Render a one-shot subcommand outcome: under `--json` emit the success/error envelope
/// to stdout; otherwise print the human summary (success → stdout, errors → stderr).
/// Returns the exit code.
fn render(result: std::io::Result<Outcome>, action: &str, json: bool) -> ExitCode {
    match result {
        Ok(outcome) => {
            if json {
                println!("{}", success_envelope(action, outcome.result));
            } else {
                println!("{}", outcome.summary);
            }
            ExitCode::Ok
        }
        Err(e) => emit_error(&e, action, json),
    }
}

/// Render `status`: success either way, but `serving:false` maps to exit 1
/// (`NOT_SERVING`) so scripts can gate on liveness.
fn render_status(result: std::io::Result<Outcome>, action: &str, json: bool) -> ExitCode {
    match result {
        Ok(outcome) => {
            let serving = outcome.result["serving"].as_bool().unwrap_or(false);
            if json {
                println!("{}", success_envelope(action, outcome.result));
            } else {
                println!("{}", outcome.summary);
            }
            if serving {
                ExitCode::Ok
            } else {
                ExitCode::NotServing
            }
        }
        Err(e) => emit_error(&e, action, json),
    }
}

/// Render the `run`/`run-service` path. These block until shutdown; a clean exit is
/// success, a bind/IO error is the typed failure. (No success object is printed — the
/// process simply runs; the startup log goes to stderr from `serve`.)
fn render_serve(result: std::io::Result<()>, action: &str, json: bool) -> ExitCode {
    match result {
        Ok(()) => ExitCode::Ok,
        Err(e) => emit_error(&e, action, json),
    }
}

/// Emit a failure: under `--json` the structured error envelope to stdout, else the
/// `error: …` line to stderr. Maps the io::Error to the differentiated exit code.
fn emit_error(e: &std::io::Error, action: &str, json: bool) -> ExitCode {
    let exit = ExitCode::from_io_error(e);
    let message = e.to_string();
    let hint = hint_for(exit);
    if json {
        println!("{}", error_envelope(action, exit, &message, hint));
    } else {
        eprintln!("error: {message}");
        if let Some(h) = hint {
            eprintln!("hint: {h}");
        }
    }
    exit
}

/// A remediation hint for an exit class (shown to humans, carried in the JSON error
/// envelope's `hint`).
fn hint_for(exit: ExitCode) -> Option<&'static str> {
    match exit {
        ExitCode::PermissionDenied => {
            Some("Re-run in a terminal opened with \"Run as administrator\" (Windows).")
        }
        ExitCode::BindFailed => {
            Some("The port is in use or unavailable; set DIG_NODE_PORT to a free port.")
        }
        _ => None,
    }
}

/// Build the multi-threaded tokio runtime and serve. Kept here (not in [`crate::server`])
/// so the lib's `serve` stays a plain async fn callers can drive on their own runtime.
fn block_on_serve(config: Config) -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(config))
}

/// The Windows-service entrypoint: hand control to the SCM dispatcher (it builds its own
/// runtime around the serve loop and reports Running/Stopped). On non-Windows there is no
/// SCM, so this just runs in the foreground like `run`.
#[cfg(windows)]
fn run_service(_config: Config) -> std::io::Result<()> {
    crate::win_service::run()
}
#[cfg(not(windows))]
fn run_service(config: Config) -> std::io::Result<()> {
    block_on_serve(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_name_prefers_arg0_file_stem() {
        // A full path resolves to the bare stem; the `.exe` suffix is stripped.
        assert_eq!(
            bin_name_from_arg0(Some(OsStr::new("/usr/bin/dign"))),
            "dign"
        );
        assert_eq!(bin_name_from_arg0(Some(OsStr::new("dign.exe"))), "dign");
        assert_eq!(
            bin_name_from_arg0(Some(OsStr::new("/opt/dig/dig-node"))),
            "dig-node"
        );
        // A bare name with no extension is returned as-is.
        assert_eq!(bin_name_from_arg0(Some(OsStr::new("dig-node"))), "dig-node");
    }

    #[test]
    fn bin_name_falls_back_to_dig_node_when_absent_or_empty() {
        assert_eq!(bin_name_from_arg0(None), "dig-node");
        assert_eq!(bin_name_from_arg0(Some(OsStr::new(""))), "dig-node");
    }

    #[test]
    fn cli_definition_is_valid() {
        // clap's derived command builds without a malformed-definition panic.
        Cli::command().debug_assert();
    }
}
