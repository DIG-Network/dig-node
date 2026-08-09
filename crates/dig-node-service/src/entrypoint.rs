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
use crate::service::ScopeChoice;
use crate::{serve, service, VERSION};

/// The shared `--scope <auto|system|user>` flag carried by every service verb (#526).
///
/// Flattened into each verb rather than declared four times, so the flag's spelling, default and
/// help text can never drift between `install`, `uninstall`, `start` and `stop`. The default is
/// `auto`, so a caller that passes no flag at all — including a dig-installer release predating
/// this flag — behaves exactly as it did before.
#[derive(clap::Args)]
struct ScopeArg {
    /// Which OS scope to act on: `system` (machine-wide, starts at boot, needs root/Administrator),
    /// `user` (per-user, no elevation, starts with your login session), or `auto` — system when
    /// running elevated, user otherwise. Windows has only system scope.
    #[arg(long = "scope", value_enum, default_value_t = ScopeChoice::Auto)]
    choice: ScopeChoice,
}

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
    Install {
        #[command(flatten)]
        scope: ScopeArg,
    },
    /// Remove the OS service.
    Uninstall {
        #[command(flatten)]
        scope: ScopeArg,
    },
    /// Start the installed service.
    Start {
        #[command(flatten)]
        scope: ScopeArg,
    },
    /// Stop the running service.
    Stop {
        #[command(flatten)]
        scope: ScopeArg,
    },
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
    /// Read a public address's balance (the OPEN `control.wallet.balance` read, #1851).
    Wallet {
        #[command(subcommand)]
        action: WalletCommand,
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

/// `dig-node wallet` sub-actions (#1851, dig_ecosystem#2376).
#[derive(Subcommand)]
enum WalletCommand {
    /// Print the balance of a public address (READ-ONLY; needs no seed or pairing).
    Balance {
        /// The bech32m address to read (`xch1…`).
        address: String,
        /// The asset to total: `xch` (default) or `dig`.
        #[arg(long, default_value = "xch")]
        asset: String,
    },
    /// List the unspent coins at a public address (READ-ONLY; needs no seed or pairing).
    Coins {
        /// The bech32m address to read (`xch1…`).
        address: String,
        /// The asset to list: `xch` (default) or `dig`.
        #[arg(long, default_value = "xch")]
        asset: String,
    },
    /// Print the chain peak this node reads against (READ-ONLY).
    Peak,
    /// Push an ALREADY-SIGNED spend bundle to the mempool.
    ///
    /// The bundle arrives complete: this verb holds no key and signs nothing. A bundle spending
    /// the NODE's own custodied coins is refused unless `DIG_WALLET_ENABLE_LIVE_BROADCAST` is on
    /// (§18.12) — sending the node's own money is a separate, default-OFF custody decision.
    Broadcast {
        /// Hex of the signed `SpendBundle` to relay.
        signed_bundle_hex: String,
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
    /// Test each tier of the connection ladder against a peer and report which one works.
    Ping {
        /// The peer to test: a 64-hex peer_id, or a dialable address (`host:port`, IPv6 bracketed).
        peer: String,
        /// Pin the peer_id the presented certificate must derive. Required when testing an address
        /// this node does not already know an identity for — an identity-less dial could only say
        /// whether a port is open, which is not a peer connection.
        #[arg(long)]
        peer_id: Option<String>,
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
            Command::Install { .. } => "install",
            Command::Uninstall { .. } => "uninstall",
            Command::Start { .. } => "start",
            Command::Stop { .. } => "stop",
            Command::Status => "status",
            Command::Pair { .. } => "pair",
            Command::Open { .. } => "open",
            Command::Info => "info",
            Command::Config { .. } => "config",
            Command::Cache { .. } => "cache",
            Command::Stores { .. } => "stores",
            Command::Sync { .. } => "sync",
            Command::Wallet { .. } => "wallet",
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
    // Mount the shared `logs` verb set (#553) beside the derived subcommands so
    // `dig-node logs path|tail|level|bundle` behaves identically to every other DIG service
    // binary. It is not part of the derived `Cli` enum, so we intercept it from the raw
    // matches BEFORE `from_arg_matches` (which would reject the unknown subcommand).
    let matches = Cli::command()
        .name(bin_static)
        .bin_name(bin)
        .subcommand(dig_logging::logs::command())
        .get_matches();
    if let Some(("logs", logs_matches)) = matches.subcommand() {
        return run_logs(logs_matches);
    }
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    // A SERVICE run must resolve its identity seed + cache under the machine state dir rather
    // than under $HOME, which the packaged unit's `ProtectHome=true` makes unreadable (#1928 —
    // without this a stock install starts with no identity and the peer network never comes up).
    // Done HERE, before the runtime and any thread exists, because it writes process environment.
    crate::state::anchor_service_data_dirs();

    let json = cli.json;
    let config = Config::from_env();
    let command = cli.command.unwrap_or(Command::Run);
    let action = command.action();

    // `run` / `run-service` serve indefinitely — they have no terminal Outcome.
    // Everything else returns an Outcome we render as JSON or prose.
    let exit = match command {
        Command::Run => render_serve(block_on_serve(config), action, json),
        Command::RunService => render_serve(run_service(config), action, json),
        Command::Install { scope } => render(service::install(&config, scope.choice), action, json),
        Command::Uninstall { scope } => render(service::uninstall(scope.choice), action, json),
        Command::Start { scope } => render(service::start(scope.choice), action, json),
        Command::Stop { scope } => render(service::stop(scope.choice), action, json),
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
        Command::Wallet { action: cmd } => {
            render(control_cli::run(&config, wallet_action(cmd)), action, json)
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

/// Map the `wallet` subcommand to its [`ControlAction`] (#1851, dig_ecosystem#2376).
fn wallet_action(cmd: WalletCommand) -> ControlAction {
    match cmd {
        WalletCommand::Balance { address, asset } => {
            ControlAction::WalletBalance { address, asset }
        }
        WalletCommand::Coins { address, asset } => ControlAction::WalletCoins { address, asset },
        WalletCommand::Peak => ControlAction::WalletPeak,
        WalletCommand::Broadcast { signed_bundle_hex } => {
            ControlAction::WalletBroadcast { signed_bundle_hex }
        }
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
        Some(PeersCommand::Ping { peer, peer_id }) => PeersAction::Ping { peer, peer_id },
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

/// Run the shared `logs` verb set (#553): `dig-node logs path|tail|level|bundle`. The verbs
/// operate on the on-disk log files (SPEC §8.1); `logs level <filter>` PERSISTS the level (it
/// takes effect on the next node start) and ADDITIONALLY live-applies it to a running node via
/// `control.log.setLevel` (best-effort — a not-running node is not an error for the persist).
fn run_logs(matches: &clap::ArgMatches) -> std::process::ExitCode {
    let service = crate::logging::service(crate::logging::run_context());
    if let Err(e) = dig_logging::logs::run(&service, matches) {
        eprintln!("error: {e}");
        return std::process::ExitCode::from(ExitCode::IoError.code());
    }
    live_apply_level(matches);
    std::process::ExitCode::from(ExitCode::Ok.code())
}

/// After `logs level <filter>` persisted the directive, push it to a RUNNING node so the change
/// takes effect immediately rather than only on the next start (SPEC §5 runtime reload). Purely
/// best-effort: a node that is not running (or rejects the directive) leaves the persisted level
/// in place and prints an informational note — never a failure, since the persist already
/// succeeded.
fn live_apply_level(logs_matches: &clap::ArgMatches) {
    let Some(("level", level_matches)) = logs_matches.subcommand() else {
        return;
    };
    let Some(filter) = level_matches.get_one::<String>("filter") else {
        return; // `logs level` with no argument only READS the level; nothing to apply.
    };
    let config = Config::from_env();
    let params = serde_json::json!({ "filter": filter });
    match crate::control_client::call_control(&config, "control.log.setLevel", params) {
        Ok(_) => eprintln!("applied to the running node (effective now)"),
        Err(_) => eprintln!("(the running node was not reachable; level applies on next start)"),
    }
}

/// Build the multi-threaded tokio runtime and serve. Kept here (not in [`crate::server`])
/// so the lib's `serve` stays a plain async fn callers can drive on their own runtime.
///
/// Installs the structured-logging stack (#553) FIRST so the bring-up narration + every
/// `dig_node_core` event lands in the rolling JSONL file + stderr for the whole serve
/// lifetime. The run context (machine vs dev-fallback log dir) mirrors the #501 daemon/CLI
/// split — an installed service logs to the machine dir, a bare `dig-node run` to the per-user
/// dev dir.
fn block_on_serve(config: Config) -> std::io::Result<()> {
    crate::logging::init(crate::logging::run_context());
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

    /// The `control.*` method a real argv reaches, or `None` if the parser rejects it.
    ///
    /// Goes through [`Cli::try_parse_from`] rather than constructing a [`ControlAction`] directly:
    /// that is the whole point of these tests (see below).
    fn method_for_argv(argv: &[&str]) -> Option<&'static str> {
        match Cli::try_parse_from(argv).ok()?.command? {
            Command::Wallet { action } => Some(wallet_action(action).method()),
            _ => None,
        }
    }

    /// **Every wallet control method is reachable from an argv a user can actually type.**
    ///
    /// `control_cli::cli_covered_control_methods` is the drift gate that claims each `control.*`
    /// method has a CLI verb, but it builds its own list out of `ControlAction` variants — so it
    /// was satisfiable by adding a variant and nothing else, which is exactly what happened to
    /// `control.wallet.{coins,peak,broadcast}` (dig_ecosystem#2376): three variants existed, the
    /// gate passed, and `dig-node wallet coins` was an unknown subcommand.
    ///
    /// This test cannot be satisfied that way. Its input is a COMMAND LINE, so it fails unless the
    /// clap parser really accepts the verb, and the assertion is on the dispatched method, so it
    /// also fails if the verb parses but maps to the wrong one.
    #[test]
    fn every_wallet_control_method_is_reachable_from_a_real_command_line() {
        let address = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";
        for (argv, expected) in [
            (
                vec!["dig-node", "wallet", "balance", address],
                "control.wallet.balance",
            ),
            (
                vec!["dig-node", "wallet", "coins", address],
                "control.wallet.coins",
            ),
            (vec!["dig-node", "wallet", "peak"], "control.wallet.peak"),
            (
                vec!["dig-node", "wallet", "broadcast", "deadbeef"],
                "control.wallet.broadcast",
            ),
        ] {
            assert_eq!(
                method_for_argv(&argv),
                Some(expected),
                "`{}` must dispatch {expected}",
                argv.join(" ")
            );
        }
    }

    /// **The parsed arguments reach the wire, not just the method name.**
    ///
    /// The nearest wrong implementation maps every new verb onto the right method while dropping
    /// its operands — `wallet coins <addr>` reading some other address, `wallet broadcast <hex>`
    /// pushing nothing. Each verb is given a value only IT could carry, and the emitted params are
    /// asserted to contain it.
    #[test]
    fn wallet_verbs_carry_their_operands_onto_the_wire() {
        let address = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";
        let coins = Cli::try_parse_from(["dig-node", "wallet", "coins", address, "--asset", "dig"])
            .expect("`wallet coins --asset` parses");
        let Some(Command::Wallet { action }) = coins.command else {
            panic!("parsed to something other than `wallet`");
        };
        assert_eq!(
            wallet_action(action).wire_params(),
            serde_json::json!({ "address": address, "asset": "dig" }),
            "the address and the non-default asset must both survive the mapping"
        );

        let push = Cli::try_parse_from(["dig-node", "wallet", "broadcast", "0xfeed"])
            .expect("`wallet broadcast <hex>` parses");
        let Some(Command::Wallet { action }) = push.command else {
            panic!("parsed to something other than `wallet`");
        };
        assert_eq!(
            wallet_action(action).wire_params(),
            serde_json::json!({ "signed_bundle_hex": "0xfeed" }),
            "the bundle the operator typed must be the bundle that is pushed"
        );
    }
}
