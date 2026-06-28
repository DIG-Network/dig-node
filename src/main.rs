//! dig-companion CLI — the entrypoint for both manual runs and the OS service.
//!
//! Subcommands:
//!   run        Run the companion in the foreground (the service entrypoint too).
//!   install    Register the companion as an auto-starting OS service.
//!   uninstall  Remove the OS service.
//!   start      Start the installed service.
//!   stop       Stop the running service.
//!   status     Report whether the companion is serving (probes /health).
//!
//! With no subcommand, `dig-companion` runs in the foreground (equivalent to
//! `run`), so a bare invocation just serves — the least-surprise default for a
//! localhost endpoint.

use clap::{Parser, Subcommand};
use dig_companion::config::Config;
use dig_companion::{serve, service, VERSION};

#[derive(Parser)]
#[command(
    name = "dig-companion",
    version = VERSION,
    about = "Localhost DIG node for the DIG Chrome extension (installable as an OS service)",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the companion in the foreground (also the unix-service entrypoint).
    Run,
    /// Internal: the Windows-service entrypoint (speaks the SCM service protocol).
    /// Installed by `install` on Windows; not meant to be run by hand. On non-Windows
    /// it behaves like `run`.
    #[command(hide = true)]
    RunService,
    /// Register the companion as an auto-starting OS service.
    Install,
    /// Remove the OS service.
    Uninstall,
    /// Start the installed service.
    Start,
    /// Stop the running service.
    Stop,
    /// Report whether the companion is serving (probes /health).
    Status,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let config = Config::from_env();

    let result: std::io::Result<()> = match cli.command.unwrap_or(Command::Run) {
        Command::Run => run(config),
        Command::RunService => run_service(config),
        Command::Install => service::install(&config),
        Command::Uninstall => service::uninstall(),
        Command::Start => service::start(),
        Command::Stop => service::stop(),
        // `status` returns whether it is serving; map "not serving" to a non-zero
        // exit so scripts can gate on it, while still printing the human message.
        Command::Status => match service::status(&config) {
            Ok(true) => Ok(()),
            Ok(false) => return std::process::ExitCode::from(1),
            Err(e) => Err(e),
        },
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
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
    dig_companion::win_service::run()
}
#[cfg(not(windows))]
fn run_service(config: Config) -> std::io::Result<()> {
    run(config)
}
