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
use serde_json::{json, Value};

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

/// The sentence printed when the rolling log FILE could not be opened and this run is
/// console-only.
///
/// A named constant rather than an inline literal for two reasons. It is the only part of the
/// degrade path a test can hold onto -- `init` installs a global subscriber, so the emission
/// itself is not assertable in-process. And it was shipped carrying two runs of ~22 literal
/// spaces from a lost string continuation, which no test could see and which renders in an
/// operator's log as a line that looks corrupted at the exact moment they are trying to work out
/// whether logging is broken.
///
/// `concat!` rather than a `\`-continued literal, and that is not a style preference: the first
/// repair here DID use continuations, and `cargo fmt` rejoined them and materialised the leading
/// indentation back into the string -- reintroducing the very defect, silently, between writing
/// the fix and running it. `the_announcement_text_has_no_lost_string_continuation` caught it.
/// `concat!` has no whitespace a formatter can reinterpret.
pub const FILE_LOGGING_DEGRADED: &str = concat!(
    "the rolling log FILE could not be opened; this run logs to the console ONLY. ",
    "Nothing is being written to that directory -- an empty log directory here means ",
    "logging was denied, not that the node was quiet."
);

/// Whether a run must ANNOUNCE that file logging degraded, given the sink's error (if any).
///
/// Pure, and separated from [`init`] for the same reason `remedy_for_unreadable_token` takes its
/// platform as an argument: the branch that matters runs on the half of the fleet where the log
/// directory is denied, which is not the machine the tests run on.
pub fn degrade_announcement(file_error: Option<&str>) -> Option<&str> {
    file_error
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
            // ANNOUNCE a degrade, do not merely record it (dig-node#392). `control.status` has
            // carried `file_error` since the 0.2.0 uplift, but nothing was said at the moment it
            // happened -- so on a non-admin run denied `C:\ProgramData\DigNetwork\logs` the node
            // came up console-only in silence, and an operator later found an empty log directory
            // with no way to tell "nothing went wrong" from "logging never started". The console
            // layer IS installed on this path, which is precisely why the warning reaches someone.
            if let Some(reason) = degrade_announcement(guard.file_error()) {
                tracing::warn!(
                    dir = %guard.log_dir().display(),
                    reason = %reason,
                    "{FILE_LOGGING_DEGRADED}"
                );
            }
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

/// Why the rolling JSONL file sink FAILED TO OPEN when this process installed logging, or `None`
/// when it opened successfully (or when this process never installed logging at all — see
/// [`initialized`]).
///
/// This is a START-UP verdict and never changes. `dig-logging` 0.2.0 computes `file_error` once
/// during `init` and exposes no mutator, so a sink failure that happens LATER — the log directory
/// deleted, the volume filled, a rotation failure — is NOT detected here and this stays `None`.
/// Reading it as "the file sink is working right now" over-claims.
///
/// Console logging is installed either way, so this is a health signal, not a failure.
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

/// The node's own logging health AS OF LOGGER INITIALIZATION, as reported by `control.status`.
/// Pure in its inputs so both arms are testable without a process-global subscriber: `file_error`
/// is [`dig_logging::LogGuard::file_error`], `dir` the resolved directory.
///
/// `file_logging: true` asserts that the rolling JSONL sink OPENED SUCCESSFULLY at start-up — not
/// that it is writing now. `dig-logging` 0.2.0 fixes `file_error` at init and offers no way to
/// revise it, so a post-init sink failure (directory deleted, volume full, rotation failure) is
/// NOT detected and this keeps reporting `true`. Widening that to live health needs post-init
/// revalidation in `dig-logging` first.
///
/// The nearest wrong implementation reports `file_logging: true` whenever logging initialised —
/// ignoring `file_error` entirely, which is the lie a start-up sink failure would then tell.
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

    /// **A live file sink announces NOTHING.** The control, and the row that makes the next one
    /// load-bearing: an implementation that warned unconditionally would satisfy the announce
    /// assertion below while shouting on every healthy start.
    #[test]
    fn a_live_file_sink_announces_no_degrade() {
        assert_eq!(degrade_announcement(None), None);
    }

    /// **A failed file sink announces, and carries the sink's own reason through.**
    ///
    /// The reason is asserted by VALUE, not merely by presence: a warning that says logging
    /// degraded without saying why sends an operator to guess between a denied directory, a full
    /// disk and a bad path -- three different remedies.
    #[test]
    fn a_failed_file_sink_announces_and_names_the_reason() {
        assert_eq!(
            degrade_announcement(Some("Access is denied. (os error 5)")),
            Some("Access is denied. (os error 5)")
        );
    }

    /// **The announcement text carries no run of collapsed whitespace.**
    ///
    /// This is not style. The message shipped with two runs of ~22 literal spaces, left behind
    /// when a Rust string continuation lost its trailing backslash -- the compiler is perfectly
    /// happy, every other test stays green, and the only witness is an operator reading a line
    /// that looks corrupted at the moment they are trying to establish whether logging works.
    #[test]
    fn the_announcement_text_has_no_lost_string_continuation() {
        assert!(
            !FILE_LOGGING_DEGRADED.contains("  "),
            concat!(
                "a run of consecutive spaces means a continuation lost its backslash: ",
                "{FILE_LOGGING_DEGRADED:?}"
            ),
            FILE_LOGGING_DEGRADED = FILE_LOGGING_DEGRADED
        );
    }

    /// **The announcement distinguishes "denied" from "quiet".**
    ///
    /// The whole point of #392: an empty log directory is ambiguous, and the warning exists to
    /// resolve the ambiguity rather than to record that something happened. A message that said
    /// only "file logging failed" would pass a presence check and leave the ambiguity intact.
    #[test]
    fn the_announcement_says_an_empty_directory_means_denied_not_quiet() {
        assert!(
            FILE_LOGGING_DEGRADED.contains("console ONLY"),
            "{FILE_LOGGING_DEGRADED}"
        );
        assert!(
            FILE_LOGGING_DEGRADED.contains("logging was denied, not that the node was quiet"),
            "the message must resolve the empty-directory ambiguity: {FILE_LOGGING_DEGRADED}"
        );
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
