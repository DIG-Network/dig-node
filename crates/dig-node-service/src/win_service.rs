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
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::Config;
use crate::server::serve_with_shutdown;
use crate::service::SERVICE_LABEL;
use crate::service_control::{
    release_runtime, run_until_stopped, StopOutcome, StopSignal, GRACEFUL_STOP_DEADLINE,
};

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
        // The service body installs structured logging early (#553), so a failure here is captured
        // in the machine log file; the non-zero exit is still reported to the SCM below.
        tracing::error!(error = %e, "dig-node service body exited with an error");
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

    // Install structured logging (#553) NOW — a Windows service has no console, so before this the
    // SCM-launched process produced NO log at all. The env above is already set, so this logs as a
    // SERVICE run into the machine log dir. Best-effort: a logging failure never blocks the service.
    crate::logging::init(dig_logging::RunContext::Service);

    let config = Config::from_env();

    // The stop signal the control handler raises and the serve path waits on
    // (dig_ecosystem#2880).
    //
    // This was a `std::sync::mpsc` pair whose receiver was awaited via
    // `spawn_blocking(recv)`, which put the stop path on tokio's BLOCKING POOL — the same
    // pool the wallet replica's synchronous database work uses. With the pool saturated
    // the receiving task never ran, so an accepted stop was never acted on and the
    // service stayed `Running` while still serving HTTP: the 1061 wedge. `StopSignal` is
    // delivered by the async runtime itself and needs no blocking thread.
    let stop_signal = StopSignal::new();

    let handler_stop = stop_signal.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // The SCM polls for status; always succeed.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                // Raising a stop neither blocks nor fails, so this handler always answers
                // the SCM promptly whatever the rest of the process is doing. That is the
                // property the whole fix rests on.
                handler_stop.request();
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

    // Same start-up wallet check the foreground entrypoint runs (#277). The SCM path does not go
    // through `block_on_serve`, so it needs its own call — a service install is the case where
    // there is most certainly no user present to create a seed.
    crate::wallet_bootstrap::ensure_wallet_seed();

    // Build the runtime and serve, shutting down when the control handler fires.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    // Two waiters on the one signal: the serve body winds itself down on the first, and
    // `run_until_stopped` bounds how long that is allowed to take on the second.
    let body_stop = stop_signal.waiter();
    let supervisor_stop = stop_signal.waiter();
    let (result, outcome) = rt.block_on(async move {
        let body = serve_with_shutdown(config, body_stop.wait());
        run_until_stopped(body, supervisor_stop, GRACEFUL_STOP_DEADLINE).await
    });

    // Report stopped regardless of the serve result; carry a non-zero exit on error
    // so the SCM (and `sc query`) reflect a failed run.
    //
    // A FORCED stop counts as a failed run on purpose (dig_ecosystem#2880): the service
    // did stop, but its body never wound down, and reporting that as a clean exit would
    // be the same class of lie as the updater's `Deferred` behind exit code 0.
    let exit = match (&result, outcome) {
        (Some(Ok(())), StopOutcome::Graceful) => 0,
        _ => 1,
    };
    if outcome == StopOutcome::Forced {
        tracing::error!(
            deadline_secs = GRACEFUL_STOP_DEADLINE.as_secs(),
            "the service body did not wind down within the graceful-stop deadline; \
             reporting Stopped anyway so the service manager can always stop this service"
        );
    }
    let _ = status_handle.set_service_status(set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
    ));
    // Release the runtime in the way this outcome allows (dig_ecosystem#2880). A forced stop
    // MUST NOT drop it: `Runtime::drop` joins the blocking pool with no timeout, and the whole
    // definition of a forced stop is that something blocking never finished — so dropping here
    // would block forever, after the SCM has already been told `Stopped`.
    release_runtime(rt, outcome);
    if outcome == StopOutcome::Forced {
        // The abandoned pool still holds a live OS thread, so leave by the one exit that cannot
        // be held up by it. The SCM already has the status and the exit code above; unwinding
        // back through the dispatcher would only give that leaked thread another chance to
        // outlive the stop the user asked for.
        std::process::exit(exit as i32);
    }
    // A forced stop has no serve result; the non-zero exit above already carries that
    // fact to the SCM, so the process itself exits cleanly rather than double-reporting.
    result.unwrap_or(Ok(()))
}
