//! Structured logging for the `dig-node` binary (#553), built on the shared
//! [`dig_logging`] building block (#547).
//!
//! Before this module the node's engine library ([`dig_node_core`]) and its P2P/TLS stack
//! emitted `tracing` events into the void: no subscriber was ever installed, so every event
//! was silently dropped and a Windows-service run produced no log at all. [`init`] installs
//! the shared dual sink — a rolling daily JSONL file in the per-OS machine log dir plus
//! compact human text on stderr — behind one reloadable level filter, so the node is
//! debuggable in the field.
//!
//! ## One process-wide guard
//!
//! `tracing` has exactly ONE global subscriber per process, so the log guard is a
//! process-global too: [`init`] stores the returned [`dig_logging::LogGuard`] in a
//! [`OnceLock`] that lives for the process lifetime (dropping the guard would flush + detach
//! the file writer). Keeping it here — rather than threading it through `serve`'s signature
//! and every test caller — mirrors the global nature of the subscriber and lets the control
//! plane reach the reload handle ([`set_level`]) without plumbing.
//!
//! ## Where it is initialised
//!
//! Only the SERVE entrypoints call [`init`] (the foreground `run`, the unix daemon, and the
//! Windows service body) — a one-shot CLI command like `status` or `pair` neither needs a
//! rolling log file nor should spawn the maintenance thread. The [`dig_logging::RunContext`]
//! distinguishes an installed-service run (machine log dir) from an interactive `dig-node
//! run` (per-user dev-fallback dir); the crate resolves the actual directory (SPEC §3).

use std::sync::OnceLock;

use dig_logging::{LogGuard, RunContext, Service};
use serde_json::{Value, json};

use crate::meta::{SERVICE_NAME, VERSION};

/// The process-global log guard. Set once by [`init`]; holding it here keeps the file writer
/// alive for the process lifetime and gives [`set_level`] the reload handle.
static GUARD: OnceLock<LogGuard> = OnceLock::new();

/// The [`Service`] identity every `dig-logging` call for this binary uses. `run_context` is a
/// label on each record (and the dev-vs-machine dir hint); the resolved directory itself
/// depends only on `name` + privilege, so the `logs` verbs (which pass [`RunContext::Cli`])
/// resolve the SAME directory the running service writes to (SPEC §3).
pub fn service(run_context: RunContext) -> Service {
    Service {
        name: SERVICE_NAME,
        version: VERSION,
        run_context,
    }
}

/// The run context this process is in: an installed OS-service run logs as
/// [`RunContext::Service`] (machine log dir), a bare `dig-node run` / dev invocation as
/// [`RunContext::Cli`] (per-user dev-fallback dir). Mirrors the #501 daemon/CLI state-dir
/// split so logs land beside the state the same run resolves.
pub fn run_context() -> RunContext {
    if crate::state::running_as_service() {
        RunContext::Service
    } else {
        RunContext::Cli
    }
}

/// Install the shared logging stack for a SERVE run (SPEC §1) and hold the guard for the
/// process lifetime. Idempotent + best-effort: a second call (e.g. a test that serves twice
/// in one process) is a silent no-op.
///
/// Since `dig-logging` 0.2.0 an unwritable log directory is NO LONGER an `init` failure: the
/// crate degrades to console-only logging and reports the reason via
/// [`dig_logging::LogGuard::file_error`], which this module re-exports as [`file_error`] and
/// `control.status` surfaces. That is the whole point of the uplift — under 0.1.x the same
/// condition returned `Err`, the stderr layer was never installed, and an interactive
/// `dig-node run` on a host whose machine log dir belongs to the service account ran with NO
/// subscriber at all, i.e. completely silent.
///
/// The remaining `Err` arm is therefore narrow — a subscriber is already installed by this
/// process, or (per the crate's docs, not reachable in practice) an unparseable filter. It is
/// still reported on stderr and swallowed, because a logging problem must NEVER stop the node
/// from serving.
pub fn init(run_context: RunContext) {
    if GUARD.get().is_some() {
        return;
    }
    match dig_logging::init(service(run_context)) {
        Ok(guard) => {
            // A `set` race (two serve paths initialising at once) is benign: the first guard
            // wins and stays live; a losing guard is dropped, which only detaches a writer
            // that was never wired into the global subscriber.
            let _ = GUARD.set(guard);
        }
        Err(e) => {
            eprintln!(
                "dig-node: WARN could not install structured logging ({e}); \
                 continuing without a subscriber"
            );
        }
    }
}

/// Why the rolling JSONL file sink is disabled for this process, or `None` when it is live (or
/// when this process never installed logging at all — see [`initialized`]).
///
/// Console logging is installed either way, so this is a health signal, not a failure: a node
/// that reported healthy logging while writing to nothing would be the exact untruth the
/// `dig-logging` 0.2.0 uplift exists to remove.
pub fn file_error() -> Option<String> {
    GUARD.get()?.file_error().map(str::to_owned)
}

/// The log directory this process resolved. When [`file_error`] is set, NOTHING is being written
/// there — it is the directory that could not be opened, which is what makes it worth reporting.
pub fn log_dir() -> Option<std::path::PathBuf> {
    GUARD.get().map(|g| g.log_dir().to_path_buf())
}

/// Whether a serve path installed the logging stack in this process.
pub fn initialized() -> bool {
    GUARD.get().is_some()
}

/// The node's own logging health, as reported by `control.status`. Pure in its inputs so both
/// arms are testable without a process-global subscriber: `file_error` is
/// [`dig_logging::LogGuard::file_error`], `dir` the resolved directory.
///
/// The nearest wrong implementation reports `file_logging: true` whenever logging initialised —
/// which is precisely the lie a degraded file sink makes possible.
pub fn health(initialized: bool, dir: Option<&std::path::Path>, file_error: Option<&str>) -> Value {
    json!({
        "initialized": initialized,
        "dir": dir.map(|d| d.display().to_string()),
        "file_logging": initialized && file_error.is_none(),
        "file_error": file_error,
    })
}

/// Record one JSON-RPC dispatch for per-request diagnosis (SPEC §6), at `DEBUG` so it stays off
/// the default `INFO` operator view. A fresh `op_id` correlates every log line emitted while
/// serving this request.
///
/// The signature is the never-log guarantee (SPEC §7): it takes ONLY the method NAME, never the
/// request `params`, so a control/pairing body — which carries the control token or a paired
/// token — is structurally unable to reach a log field through the request path. This is the ONE
/// place the transport logs an incoming request.
pub fn log_rpc_dispatch(method: &str) {
    tracing::debug!(op_id = %dig_logging::new_run_id(), rpc.method = %method, "rpc dispatch");
}

/// Live-swap the global level filter (SPEC §5 runtime reload) — the engine behind
/// `control.log.setLevel` and `dig-node logs level <filter>` against a running node. Returns
/// a human error string when logging was never initialised (this process is not a serving
/// node) or the directive is not a valid `EnvFilter` (e.g. `info,dig_node_core=debug`).
pub fn set_level(directive: &str) -> Result<(), String> {
    let guard = GUARD
        .get()
        .ok_or("logging is not initialised in this process")?;
    guard.set_filter(directive).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_identity_is_the_canonical_node_name() {
        let svc = service(RunContext::Cli);
        assert_eq!(svc.name, "dig-node");
        assert_eq!(svc.version, VERSION);
    }

    #[test]
    fn set_level_errors_before_init() {
        // In a plain `cargo test` process no serve path ran, so the guard is unset and a level
        // change reports the actionable reason rather than panicking. (This also documents that
        // `control.log.setLevel` on a non-serving process fails cleanly.)
        assert!(set_level("debug").is_err());
    }

    #[test]
    fn health_reports_file_logging_off_and_names_the_reason() {
        // The degraded case the 0.2.0 uplift exists for: the subscriber IS installed (console
        // logging works) but nothing reaches the file. A surface that reported `file_logging:
        // true` here would be the untruth being removed.
        let dir = std::path::Path::new("/var/log/dig-node");
        let value = health(true, Some(dir), Some("permission denied"));
        assert_eq!(value["initialized"], true);
        assert_eq!(value["file_logging"], false);
        assert_eq!(value["file_error"], "permission denied");
        assert_eq!(value["dir"], dir.display().to_string());
    }

    #[test]
    fn health_reports_file_logging_on_when_the_sink_is_live() {
        // The honest control for the test above: same shape, no error, so a `file_logging: false`
        // constant would fail here and a `true` constant fails there.
        let value = health(true, Some(std::path::Path::new("/tmp/logs")), None);
        assert_eq!(value["file_logging"], true);
        assert_eq!(value["file_error"], Value::Null);
    }

    #[test]
    fn health_never_claims_file_logging_when_logging_was_never_installed() {
        let value = health(false, None, None);
        assert_eq!(value["initialized"], false);
        assert_eq!(value["file_logging"], false);
        assert_eq!(value["dir"], Value::Null);
    }
}
