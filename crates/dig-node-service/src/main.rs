//! dig-node CLI — the entrypoint for both manual runs and the OS service.
//! (The binary, crate, and service all carry the canonical `dig-node` name; this is
//! the local **dig-node** service the DIG Chrome extension points `server.host` at.)
//!
//! Subcommands:
//!   run        Run the node in the foreground (the service entrypoint too).
//!   install    Register the node as an auto-starting OS service.
//!   uninstall  Remove the OS service.
//!   start      Start the installed service.
//!   stop       Stop the running service.
//!   status     Report whether the node is serving (probes /health).
//!
//! With no subcommand, the binary runs in the foreground (equivalent to `run`), so
//! a bare invocation just serves — the least-surprise default for a localhost
//! endpoint.
//!
//! ## Machine-readable output (`--json`)
//!
//! Every subcommand accepts the global `--json` flag: on success it emits ONE
//! structured object to **stdout** (`{ ok:true, action, ... }`) and routes human
//! prose to **stderr**; on failure it emits `{ ok:false, error:{ code, exit_code,
//! message, hint } }` to stdout and still exits with the differentiated code. The
//! exit-code table is documented in [`dig_node_service::cli`] and the README.

use clap::{Parser, Subcommand};
use dig_node_service::cli::{error_envelope, success_envelope, ExitCode, Outcome};
use dig_node_service::config::Config;
use dig_node_service::pair::{self, PairAction};
use dig_node_service::{serve, service, VERSION};

#[derive(Parser)]
#[command(
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
        }
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    let config = Config::from_env();
    let command = cli.command.unwrap_or(Command::Run);
    let action = command.action();

    // `run` / `run-service` serve indefinitely — they have no terminal Outcome.
    // Everything else returns an Outcome we render as JSON or prose.
    let exit = match command {
        Command::Run => render_serve(run(config), action, json),
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
    };
    std::process::ExitCode::from(exit.code())
}

/// Render a one-shot subcommand outcome: under `--json` emit the success/error
/// envelope to stdout; otherwise print the human summary (success → stdout, errors
/// → stderr). Returns the exit code.
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

/// Render the `run`/`run-service` path. These block until shutdown; a clean exit
/// is success, a bind/IO error is the typed failure. (No success object is printed
/// — the process simply runs; the startup log goes to stderr from `serve`.)
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

/// A remediation hint for an exit class (shown to humans, carried in the JSON
/// error envelope's `hint`).
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

/// Build the multi-threaded tokio runtime and serve. Kept here (not in the lib) so
/// the lib's `serve` stays a plain async fn callers can drive on their own runtime.
fn run(config: Config) -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(config))
}

/// The Windows-service entrypoint: hand control to the SCM dispatcher (it builds
/// its own runtime around the serve loop and reports Running/Stopped). On
/// non-Windows there is no SCM, so this just runs in the foreground like `run`.
#[cfg(windows)]
fn run_service(_config: Config) -> std::io::Result<()> {
    dig_node_service::win_service::run()
}
#[cfg(not(windows))]
fn run_service(config: Config) -> std::io::Result<()> {
    run(config)
}
