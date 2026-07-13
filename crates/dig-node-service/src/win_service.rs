//! Windows Service Control Protocol entrypoint (Windows only).
//!
//! Registering a service in the SCM (via `service-manager`) is not enough: the
//! executable the SCM launches must itself connect back to the SCM
//! (`StartServiceCtrlDispatcher`) and report `Running` within ~30s, or the SCM
//! kills it with error 1053 ("the service did not respond … in a timely fashion").
//! This module is that connection: the installed service runs
//! `dig-node run-service`, which calls [`run`] here to become a real Windows
//! service — registering a control handler, reporting `Running`, serving until the
//! SCM sends `Stop`, then reporting `Stopped`.
//!
//! The service is registered with the qualified label name (see
//! [`crate::service::SERVICE_LABEL`]); the name passed to the dispatcher must match
//! it exactly.

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::Config;
use crate::server::serve_with_shutdown;
use crate::service::SERVICE_LABEL;

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Hand control to the SCM dispatcher. Blocks until the service stops. Called by
/// the `run-service` subcommand (the program the installed service launches). On a
/// dispatcher error (e.g. invoked outside the SCM) it returns an io::Error so the
/// CLI can report it.
pub fn run() -> std::io::Result<()> {
    service_dispatcher::start(SERVICE_LABEL, ffi_service_main)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

// Generates `ffi_service_main`, the low-level entry the SCM calls, which forwards
// to `service_main` below.
define_windows_service!(ffi_service_main, service_main);

/// Service entry called on a background thread by the SCM. There is no stdout/stderr
/// here, so failures are surfaced only by the reported service status (a failed
/// startup leaves the SCM seeing a stopped service with a non-zero exit code).
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        // Best-effort: nothing to log to, but the non-zero exit is reported below.
        eprintln!("dig-node service error: {e}");
    }
}

/// The actual service body: register the control handler, report `Running`, run the
/// HTTP server until `Stop`, then report `Stopped`.
fn run_service() -> std::io::Result<()> {
    // Self-identify as a SERVICE run (#501): this entrypoint is reached ONLY when the Windows
    // SCM launches the installed service, so it is the authoritative place to mark the process
    // as a service — the daemon may then bootstrap the machine-wide state dir
    // (`%PROGRAMDATA%\DigNode`) if the installer did not pre-create it. Belt-and-suspenders with
    // the same env `install` writes into the service environment.
    std::env::set_var(
        crate::state::RUN_CONTEXT_ENV,
        crate::state::RUN_CONTEXT_SERVICE,
    );
    let config = Config::from_env();

    // Channel the control handler signals on `Stop`; the server's graceful-shutdown
    // future waits on it.
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // The SCM polls for status; always succeed.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_LABEL, event_handler)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Tell the SCM we are running (so it does not time out with 1053). We accept the
    // STOP control.
    let set = |state: ServiceState, accept: ServiceControlAccept, exit: u32| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle
        .set_service_status(set(ServiceState::Running, ServiceControlAccept::STOP, 0))
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Build the runtime and serve, shutting down when the control handler fires.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async move {
        // Bridge the blocking std mpsc into an async shutdown future.
        let shutdown = async move {
            // Wait on the channel on a blocking thread so we don't park the runtime.
            let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
        };
        serve_with_shutdown(config, shutdown).await
    });

    // Report stopped regardless of the serve result; carry a non-zero exit on error
    // so the SCM (and `sc query`) reflect a failed run.
    let exit = if result.is_ok() { 0 } else { 1 };
    let _ = status_handle.set_service_status(set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
    ));
    result
}
