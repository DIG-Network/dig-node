//! Beacon (`dig-updater`) RPC proxy (#515, beacon epic #504): surfaces the DIG auto-update
//! beacon's status and control over this service's `control.*` surface, so a same-host
//! controller (the extension/hub Updates UI, #516) can show + drive it without shelling out
//! itself.
//!
//! # A THIN proxy — never a second beacon
//!
//! This module never re-verifies a signed manifest, never decides what to install, and never
//! re-implements any part of the beacon's trust chain (dig-updater SPEC §§1-9) — that logic
//! belongs to the beacon ALONE. It only:
//!
//! - **reads** the beacon's world-readable `status.json` (dig-updater SPEC §13.2) directly off
//!   disk, because [`status`] is polled frequently by a UI and a file read is far cheaper than
//!   spawning a process on every poll; and
//! - **shells** the already elevation-gated `dig-updater` operator CLI (dig-updater SPEC §13.3)
//!   for every mutation (`channel set`/`pause`/`resume`) and for an on-demand check
//!   (`check --now`) — this service itself runs privileged (Windows LocalSystem / a root daemon),
//!   so it can invoke those elevation-gated commands the same way an Administrator/root operator
//!   would from a terminal.
//!
//! Both the status file and the CLI's `--json` output are treated as OPAQUE JSON: this proxy
//! never types out the beacon's wire shape, it forwards it verbatim. The beacon's own
//! schema-versioned contract (`status.json`'s `schema` field, dig-updater SPEC §13.2) exists
//! precisely so an independent reader like this one can do that safely — a new field the beacon
//! adds later simply passes through here untouched; there is no shape to keep in sync.
//!
//! # Auth
//!
//! Every method lives in the `control.updater.*` namespace, so it inherits the surrounding
//! `control.*` gate unchanged ([`crate::control::is_control_method`] /
//! [`crate::control::is_authorized`]) — no new auth surface, nothing to remember to gate.

use std::path::PathBuf;
use std::process::Stdio;

use serde_json::{json, Value};

use crate::control::{control_error, control_ok};
use crate::meta::ErrorCode;

/// Overrides where [`status_path`] reads the beacon's status mirror from — set by a test, or by
/// an operator who relocated the beacon's status directory.
pub const STATUS_DIR_ENV: &str = "DIG_UPDATER_STATUS_DIR";

/// Overrides which `dig-updater` binary [`resolve_cli_binary`] invokes — set by a test (a fake
/// fixture) or an operator whose beacon install lives at a nonstandard path.
pub const CLI_BIN_ENV: &str = "DIG_UPDATER_BIN";

/// The beacon's world-readable status directory (dig-updater SPEC §13.2): a sibling of its
/// Admin/SYSTEM-only state directory, named `<state-dir-name>-status`.
///
/// - **Windows:** `%ProgramData%\DIG\updater-status`
/// - **Unix:** `/var/lib/dig-updater-status`
///
/// [`STATUS_DIR_ENV`] overrides this outright.
fn status_dir() -> PathBuf {
    if let Some(over) = std::env::var_os(STATUS_DIR_ENV) {
        return PathBuf::from(over);
    }
    #[cfg(windows)]
    {
        let program_data =
            std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(program_data)
            .join("DIG")
            .join("updater-status")
    }
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/dig-updater-status")
    }
}

/// The beacon's `status.json` path — `<status_dir>/status.json`.
fn status_path() -> PathBuf {
    status_dir().join("status.json")
}

/// The `dig-updater` CLI's file name on this OS.
fn cli_file_name() -> &'static str {
    if cfg!(windows) {
        "dig-updater.exe"
    } else {
        "dig-updater"
    }
}

/// Resolve the `dig-updater` CLI by an ABSOLUTE path — never a bare name spawned through `PATH`,
/// the same discipline the beacon's own broker holds its OWN install path to (dig-updater SPEC
/// §8.3: "invoked by the installer's ABSOLUTE trusted path, never a bare name resolved through
/// PATH"). Checked in order:
///
/// 1. [`CLI_BIN_ENV`] — an explicit override (tests; a nonstandard install).
/// 2. Beside this running `dig-node` binary — `digstore`/`dig-node`/`dig-dns` already share ONE
///    bin dir on `PATH` (dig-installer's "CLI-on-PATH verification"), and the beacon installer
///    (#514) is expected to place `dig-updater` in that same shared dir.
/// 3. The per-OS conventional install root dig-installer uses for that shared bin dir.
///
/// `None` when no candidate exists on disk — the caller reports "beacon not installed" rather
/// than attempting an unverified spawn.
fn resolve_cli_binary() -> Option<PathBuf> {
    let name = cli_file_name();

    if let Some(over) = std::env::var_os(CLI_BIN_ENV) {
        let path = PathBuf::from(over);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(candidate) = exe.parent().map(|dir| dir.join(name)) {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    conventional_bin_dirs()
        .into_iter()
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The per-OS conventional shared bin dir dig-installer places `digstore`/`dig-node`/`dig-dns`
/// (and, once #514 ships, `dig-updater`) into.
fn conventional_bin_dirs() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let program_files =
            std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
        vec![PathBuf::from(program_files).join("DIG")]
    }
    #[cfg(unix)]
    {
        vec![
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/opt/dig/bin"),
        ]
    }
}

/// Why a `dig-updater` CLI invocation didn't yield a usable result.
#[derive(Debug)]
enum CliError {
    /// No `dig-updater` binary was found by [`resolve_cli_binary`].
    NotInstalled,
    /// The binary was found but the OS failed to spawn it.
    Spawn(String),
    /// The CLI ran and explicitly declined the request, reporting why (its own
    /// `{"status":"error","detail":...}` `--json` failure shape, non-zero exit).
    Declined(String),
    /// The CLI exited in a shape this proxy cannot interpret (a crash, an unexpected output
    /// format) — distinct from a normal, well-formed decline.
    Malformed {
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
    },
}

impl CliError {
    /// Render as the control-plane's error envelope.
    fn into_response(self, id: Value) -> Value {
        match self {
            CliError::NotInstalled => control_error(
                id,
                ErrorCode::NotSupported,
                "the DIG auto-update beacon (dig-updater) is not installed on this machine",
            ),
            CliError::Spawn(e) => control_error(
                id,
                ErrorCode::ControlError,
                format!("failed to invoke dig-updater: {e}"),
            ),
            CliError::Declined(detail) => control_error(
                id,
                ErrorCode::ControlError,
                format!("dig-updater declined the request: {detail}"),
            ),
            CliError::Malformed {
                exit_code,
                stdout,
                stderr,
            } => control_error(
                id,
                ErrorCode::ControlError,
                format!(
                    "dig-updater returned unparsable output (exit {exit_code:?}): \
                     stdout={stdout:?} stderr={stderr:?}"
                ),
            ),
        }
    }
}

/// Run the resolved `dig-updater` binary with `args` (always appending `--json` so the result is
/// machine-parseable) and classify the outcome. Every command the CLI understands supports
/// `--json` uniformly, including its failure paths (dig-updater SPEC §13.3) — a decline prints
/// `{"status":"error","detail":...}` to STDOUT (never stderr) with a non-zero exit, so both
/// outcomes are parsed the same way and told apart by the parsed shape plus exit status.
async fn run_cli(args: &[&str]) -> Result<Value, CliError> {
    let bin = resolve_cli_binary().ok_or(CliError::NotInstalled)?;
    let output = tokio::process::Command::new(&bin)
        .args(args)
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| CliError::Spawn(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let parsed: Option<Value> = serde_json::from_str(&stdout).ok();

    match (output.status.success(), parsed) {
        (true, Some(value)) => Ok(value),
        (false, Some(value)) if value.get("status").and_then(|s| s.as_str()) == Some("error") => {
            let detail = value
                .get("detail")
                .and_then(|d| d.as_str())
                .unwrap_or("no detail given")
                .to_string();
            Err(CliError::Declined(detail))
        }
        _ => Err(CliError::Malformed {
            exit_code: output.status.code(),
            stdout,
            stderr,
        }),
    }
}

/// `control.updater.status` — the beacon's status mirror, read directly off disk (never through
/// the CLI: this is the method a UI polls, and a file read is far cheaper than a process spawn on
/// every poll). Absence is a NORMAL outcome — the beacon may simply never have been installed —
/// so it is reported as `{"installed": false}`, never an error; a present-but-corrupt file is a
/// genuine anomaly worth surfacing distinctly.
pub fn status(id: Value) -> Value {
    match std::fs::read(status_path()) {
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(status) => control_ok(id, json!({ "installed": true, "status": status })),
            Err(e) => control_error(
                id,
                ErrorCode::ControlError,
                format!("beacon status.json is present but not valid JSON: {e}"),
            ),
        },
        Err(_) => control_ok(id, json!({ "installed": false })),
    }
}

/// `control.updater.setChannel` — set the beacon's update channel. Params: `{ "channel": "alpha" }`.
pub async fn set_channel(id: Value, params: &Value) -> Value {
    let Some(channel) = params.get("channel").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.updater.setChannel requires params.channel (a string, e.g. \"alpha\")",
        );
    };
    match run_cli(&["channel", "set", channel]).await {
        Ok(result) => control_ok(id, result),
        Err(e) => e.into_response(id),
    }
}

/// `control.updater.pause` — suspend the beacon's auto-updates. Params: `{ "until": <unix_secs> }`
/// (optional — an omitted `until` pauses indefinitely, until an explicit `resume`).
pub async fn pause(id: Value, params: &Value) -> Value {
    let until = params
        .get("until")
        .and_then(|v| v.as_u64())
        .map(|u| u.to_string());
    let mut args: Vec<&str> = vec!["pause"];
    if let Some(until) = until.as_deref() {
        args.push("--until");
        args.push(until);
    }
    match run_cli(&args).await {
        Ok(result) => control_ok(id, result),
        Err(e) => e.into_response(id),
    }
}

/// `control.updater.resume` — resume the beacon's auto-updates (clears any pause).
pub async fn resume(id: Value) -> Value {
    match run_cli(&["resume"]).await {
        Ok(result) => control_ok(id, result),
        Err(e) => e.into_response(id),
    }
}

/// `control.updater.checkNow` — trigger an on-demand FULL update pass (`dig-updater check --now`),
/// identical gating to the beacon's own daily schedule. Synchronous: the call blocks until the
/// pass completes (a real pass — fetch, verify, install behind the health gate — can take a
/// while; the caller is expected to show its own progress state, not treat this as instant).
pub async fn check_now(id: Value) -> Value {
    match run_cli(&["check", "--now"]).await {
        Ok(result) => control_ok(id, result),
        Err(e) => e.into_response(id),
    }
}

// The CLI-spawn tests (`set_channel`/`pause`/`resume`/`check_now` run against the real
// `fake_beacon_cli` fixture binary) live in `tests/beacon_cli_process.rs` instead of here:
// `env!("CARGO_BIN_EXE_fake_beacon_cli")` is only defined for INTEGRATION test targets
// (Cargo book, "Environment variables Cargo sets for build scripts"), not for a crate's own
// `--lib` unit-test harness that this `#[cfg(test)]` module compiles into.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    use tokio::sync::Mutex;

    /// Serializes tests in this file that mutate the process-global env vars
    /// ([`STATUS_DIR_ENV`], [`CLI_BIN_ENV`]) — mirrors `tests/server.rs`'s own `env_guard`. A
    /// `tokio::sync::Mutex` (not `std::sync::Mutex`): the one async test here holds the guard
    /// across an `.await`, which trips `clippy::await_holding_lock` on a std guard.
    fn env_guard() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// A unique-per-call scratch path, so concurrent test RUNS (across `cargo test`
    /// invocations) never collide even though tests within this file are serialized.
    fn unique_path(label: &str) -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "dig-node-updater-test-{label}-{}-{n}",
            std::process::id()
        ))
    }

    // -- status: read directly off disk --------------------------------------------------

    #[test]
    fn status_reports_not_installed_when_status_json_is_absent() {
        let _guard = env_guard().blocking_lock();
        let dir = unique_path("absent");
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var(STATUS_DIR_ENV, &dir);

        let resp = status(json!(1));

        assert_eq!(resp["result"]["installed"], json!(false));
        assert!(resp.get("error").is_none());
        std::env::remove_var(STATUS_DIR_ENV);
    }

    #[test]
    fn status_returns_the_file_verbatim_when_present() {
        let _guard = env_guard().blocking_lock();
        let dir = unique_path("present");
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var(STATUS_DIR_ENV, &dir);
        let body = json!({ "schema": 1, "version": "0.6.0", "channel": "alpha" });
        std::fs::write(dir.join("status.json"), serde_json::to_vec(&body).unwrap()).unwrap();

        let resp = status(json!(1));

        assert_eq!(resp["result"]["installed"], json!(true));
        assert_eq!(resp["result"]["status"], body);
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var(STATUS_DIR_ENV);
    }

    #[test]
    fn status_reports_a_control_error_on_corrupt_json_not_not_installed() {
        let _guard = env_guard().blocking_lock();
        let dir = unique_path("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var(STATUS_DIR_ENV, &dir);
        std::fs::write(dir.join("status.json"), b"{ not json").unwrap();

        let resp = status(json!(1));

        assert_eq!(resp["error"]["data"]["code"], json!("CONTROL_ERROR"));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var(STATUS_DIR_ENV);
    }

    #[test]
    fn status_dir_defaults_to_the_documented_per_os_convention_when_unset() {
        let _guard = env_guard().blocking_lock();
        std::env::remove_var(STATUS_DIR_ENV);
        let dir = status_dir();
        if cfg!(windows) {
            assert!(dir.ends_with(r"DIG\updater-status") || dir.ends_with("DIG/updater-status"));
        } else {
            assert_eq!(dir, PathBuf::from("/var/lib/dig-updater-status"));
        }
    }

    // -- param validation ------------------------------------------------------------------

    #[tokio::test]
    async fn set_channel_without_a_channel_param_is_invalid_params() {
        let resp = set_channel(json!(1), &json!({})).await;
        assert_eq!(resp["error"]["data"]["code"], json!("INVALID_PARAMS"));
    }

    // -- binary resolution -------------------------------------------------------------------

    #[test]
    fn resolve_cli_binary_prefers_the_explicit_override() {
        let _guard = env_guard().blocking_lock();
        // Any existing file proves the override wins — `resolve_cli_binary` only checks
        // `is_file()`, so a plain temp file (not a real executable) is a sufficient stand-in
        // here; the actual spawn+parse path is exercised end-to-end in `tests/updater_cli.rs`.
        let dummy = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var(CLI_BIN_ENV, dummy.path());
        assert_eq!(resolve_cli_binary(), Some(dummy.path().to_path_buf()));
        std::env::remove_var(CLI_BIN_ENV);
    }

    #[test]
    fn resolve_cli_binary_ignores_an_override_pointing_at_a_missing_file() {
        let _guard = env_guard().blocking_lock();
        let missing = PathBuf::from("/definitely/does/not/exist/dig-updater");
        std::env::set_var(CLI_BIN_ENV, &missing);
        assert_ne!(resolve_cli_binary(), Some(missing));
        std::env::remove_var(CLI_BIN_ENV);
    }

    #[tokio::test]
    async fn every_mutation_reports_not_installed_when_no_binary_resolves() {
        let _guard = env_guard().lock().await;
        // No override, and a real `dig-updater` is never present beside this test binary or
        // under the conventional install dirs on a CI runner (or a normal dev checkout) — so
        // NOT_SUPPORTED is the correct, real outcome for every mutation.
        std::env::remove_var(CLI_BIN_ENV);

        let checks = [
            (
                "setChannel",
                set_channel(json!(1), &json!({ "channel": "alpha" })).await,
            ),
            ("pause", pause(json!(1), &json!({})).await),
            ("resume", resume(json!(1)).await),
            ("checkNow", check_now(json!(1)).await),
        ];
        for (label, resp) in checks {
            assert_eq!(
                resp["error"]["data"]["code"],
                json!("NOT_SUPPORTED"),
                "{label} should report NOT_SUPPORTED with no dig-updater binary resolvable"
            );
        }
    }

    // CLI-spawn behavior (arg building, `--json` output parsing, declined/malformed
    // classification) is exercised against a REAL child process in `tests/updater_cli.rs`.
}
