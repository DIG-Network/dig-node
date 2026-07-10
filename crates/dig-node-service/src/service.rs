//! OS-service registration for dig-node, across Windows (SCM), Linux
//! (systemd) and macOS (launchd) via the `service-manager` crate.
//!
//! The whole point of the Rust rewrite: a self-contained binary that installs
//! cleanly as an OS service, with no Node runtime to depend on. `install` registers
//! `dig-node run` to auto-start and serve on the loopback port; `uninstall`
//! removes it; `start`/`stop` control the registered service; `status` reports
//! whether it is registered and actually serving.
//!
//! Install level by platform:
//!   * Linux (systemd) / macOS (launchd) — **user-level** by default (`--user` /
//!     `gui` domain), so no root/sudo is needed and the service runs as the
//!     installing user.
//!   * Windows (SCM) — **system-level only**: the Service Control Manager has no
//!     per-user services, so `install`/`uninstall` require an **elevated
//!     (Administrator)** console. This is detected up front and reported with a
//!     clear message rather than failing deep inside `sc.exe`.

use std::ffi::OsString;
use std::str::FromStr;

use serde_json::json;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

use crate::cli::Outcome;
use crate::config::Config;

/// The reverse-DNS service label. `ServiceLabel::to_qualified_name` rejoins its
/// 3 dot-separated segments unchanged, so on Windows this is used AS-IS as the SCM
/// service name (`sc.exe create`/`failure`/`start`/`stop` all address
/// `net.dignetwork.dig-node` literally); on launchd it's the plist label; on
/// systemd the unit name. Kept stable so install/uninstall/start/stop (and the
/// recovery-action config below) all address the same service.
pub const SERVICE_LABEL: &str = "net.dignetwork.dig-node";

/// Whether user-level (no-elevation) install is supported on this OS. Windows SCM
/// is system-only; systemd/launchd support a user domain.
#[cfg(windows)]
const PREFERS_USER_LEVEL: bool = false;
#[cfg(not(windows))]
const PREFERS_USER_LEVEL: bool = true;

/// Build the parsed service label (infallible for our constant, but the crate
/// returns a Result, so surface a clear error if the constant is ever mis-edited).
fn label() -> std::io::Result<ServiceLabel> {
    ServiceLabel::from_str(SERVICE_LABEL)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
}

/// Acquire the native service manager, set to user-level where the platform
/// supports it (Linux/macOS), else system-level (Windows). Returns the manager
/// plus whether it is operating at user level (for messaging).
fn manager() -> std::io::Result<(Box<dyn ServiceManager>, bool)> {
    let mut mgr = <dyn ServiceManager>::native()?;
    let mut user_level = false;
    if PREFERS_USER_LEVEL && mgr.set_level(ServiceLevel::User).is_ok() {
        user_level = true;
    }
    Ok((mgr, user_level))
}

/// Absolute path to the currently-running `dig-node` executable, so the
/// installed service points at THIS binary (not a PATH lookup that might resolve
/// to a different/absent copy).
fn current_exe() -> std::io::Result<std::path::PathBuf> {
    std::env::current_exe()
}

/// On Windows, is this process running elevated (Administrator)? Used to fail
/// `install`/`uninstall` early with a helpful message instead of a cryptic SCM
/// access-denied. Always `true` off Windows (those paths are user-level).
#[cfg(windows)]
fn is_elevated() -> bool {
    // Probe by attempting to open the SCM with all-access; only an elevated token
    // can. Shelling to `net session` is the classic check; doing it via `sc` query
    // would not distinguish. Use a lightweight `net session` invocation.
    std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
#[cfg(not(windows))]
fn is_elevated() -> bool {
    true
}

/// `sc.exe failure` recovery-action config: reset the failure counter after one
/// day of no further crashes, and restart the service 5s/10s/30s after the
/// 1st/2nd/subsequent failure in that window. Mirrors the spirit of systemd's
/// `Restart=on-failure` default (which `service-manager` already applies on
/// Linux) and launchd's `KeepAlive` (already applied on macOS) — see
/// [`configure_windows_recovery`].
const RECOVERY_RESET_SECONDS: &str = "86400";
const RECOVERY_ACTIONS: &str = "restart/5000/restart/10000/restart/30000";

/// Build the `sc.exe failure` argument list that configures restart-on-crash
/// recovery actions for `service_name`. PURE (no process spawn) so the argument
/// construction is unit-testable without invoking `sc.exe` for real.
fn recovery_action_args(service_name: &str) -> Vec<String> {
    vec![
        "failure".to_string(),
        service_name.to_string(),
        "reset=".to_string(),
        RECOVERY_RESET_SECONDS.to_string(),
        "actions=".to_string(),
        RECOVERY_ACTIONS.to_string(),
    ]
}

/// Register Windows SCM recovery actions (restart-on-crash) for the installed
/// service. `service-manager`'s `sc.rs` backend only shells out to `sc create`
/// (§`install`) — it never configures `SERVICE_CONFIG_FAILURE_ACTIONS`, and the
/// pinned `windows-service` 0.7 crate exposes no `ChangeServiceConfig2` binding
/// either, so Windows services do NOT restart on crash unless this is set
/// explicitly (unlike systemd/launchd, which `service-manager` already covers by
/// default). Call ONLY after a successful `mgr.install`; the caller treats a
/// failure here as non-fatal (see [`install`]).
#[cfg(windows)]
fn configure_windows_recovery(service_name: &str) -> std::io::Result<()> {
    let args = recovery_action_args(service_name);
    let output = std::process::Command::new("sc.exe")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        let msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let msg = if msg.is_empty() {
            format!("sc.exe failure exited with {}", output.status)
        } else {
            msg
        };
        Err(std::io::Error::other(msg))
    }
}

/// Install dig-node as an auto-starting OS service that runs
/// `dig-node run` on the configured loopback port. The service's environment
/// carries the resolved port/host/upstream so it serves identically to a manual
/// `run`. On Windows, also configures SCM recovery actions (restart-on-crash) —
/// see [`configure_windows_recovery`] — so a crashed service comes back up the
/// same way systemd (`Restart=on-failure`) and launchd (`KeepAlive`) already do
/// for Linux/macOS via `service-manager`'s own defaults.
pub fn install(config: &Config) -> std::io::Result<Outcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "dig-node: installing a Windows service requires an elevated \
             (Administrator) console. Re-run this in a terminal opened with \
             \"Run as administrator\".",
        ));
    }

    let (mgr, user_level) = manager()?;
    let program = current_exe()?;
    let svc_label = label()?;

    // Pass the effective config to the service as env vars so the running service
    // matches what `install` was told (the service process does not inherit the
    // installing shell's environment).
    let mut environment = vec![
        ("DIG_NODE_PORT".to_string(), config.port.to_string()),
        ("DIG_NODE_HOST".to_string(), config.host.to_string()),
        ("DIG_RPC_UPSTREAM".to_string(), config.upstream.clone()),
    ];
    // Only record DIG_NODE_CACHE when an explicit dir was set: omitting it lets the
    // service resolve dig-node's shared canonical default — the SAME dir the DIG
    // Browser's in-process node uses — so the two share ONE cache (#96). Recording
    // a path here pins the service to it, so an operator pointing the service at a
    // dedicated cache must set the SAME path for the browser to keep sharing.
    if let Some(dir) = crate::config::cache_dir_env_value(config.cache_dir.as_deref()) {
        environment.push(("DIG_NODE_CACHE".to_string(), dir));
    }

    // The SCM-launched program must speak the Windows service protocol, so on
    // Windows the installed service runs the hidden `run-service` entrypoint
    // (StartServiceCtrlDispatcher), not the plain foreground `run`. systemd/launchd
    // exec the foreground process directly, so they use `run`.
    let entry_arg = if cfg!(windows) { "run-service" } else { "run" };

    mgr.install(ServiceInstallCtx {
        label: svc_label.clone(),
        program: program.clone(),
        args: vec![OsString::from(entry_arg)],
        contents: None,
        username: None,
        working_directory: None,
        environment: Some(environment),
        autostart: true,
    })?;

    // Windows: best-effort SCM recovery-action config. A failure here (e.g.
    // `sc.exe` missing/blocked) must not fail the whole install — the service is
    // already registered and usable, just without auto-restart-on-crash; surface
    // it as a note instead. Linux/macOS need no equivalent step: service-manager's
    // own defaults (`Restart=on-failure` / `KeepAlive`) already cover them.
    #[cfg(windows)]
    let (recovery_configured, recovery_note) =
        match configure_windows_recovery(&svc_label.to_qualified_name()) {
            Ok(()) => (true, None),
            Err(e) => (
                false,
                Some(format!(
                    "note: could not configure Windows SCM restart-on-crash recovery \
                     actions ({e}); the service is installed but will NOT auto-restart \
                     if it crashes. Configure manually with: sc.exe failure {SERVICE_LABEL} \
                     reset= {RECOVERY_RESET_SECONDS} actions= {RECOVERY_ACTIONS}"
                )),
            ),
        };
    #[cfg(not(windows))]
    let (recovery_configured, recovery_note): (bool, Option<String>) = (true, None);

    let scope = if user_level { "user" } else { "system" };
    let addr = config.bind_addr();
    let mut summary = format!(
        "dig-node: installed as a {scope}-level service \"{SERVICE_LABEL}\"\n  \
         program: {}\n  serves:  http://{addr}\n  Set the DIG Chrome extension's \"server host\" to {addr}.\n  \
         Start it now with: dig-node start",
        program.display(),
    );
    if let Some(note) = &recovery_note {
        summary.push_str("\n  ");
        summary.push_str(note);
    }
    Ok(Outcome::new(
        summary,
        json!({
            "installed": true,
            "registered": true,
            "started": false,
            "label": SERVICE_LABEL,
            "scope": scope,
            "program": program.display().to_string(),
            "addr": addr,
            "upstream": config.upstream,
            "recovery_configured": recovery_configured,
        }),
    ))
}

/// Uninstall the dig-node service. Stops it first (best-effort) so the uninstall
/// is clean.
pub fn uninstall() -> std::io::Result<Outcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "dig-node: uninstalling a Windows service requires an elevated \
             (Administrator) console.",
        ));
    }
    let (mgr, _user) = manager()?;
    // Best-effort stop before removal (ignore "not running" errors).
    let _ = mgr.stop(ServiceStopCtx { label: label()? });
    mgr.uninstall(ServiceUninstallCtx { label: label()? })?;
    Ok(Outcome::new(
        format!("dig-node: uninstalled service \"{SERVICE_LABEL}\""),
        json!({ "installed": false, "registered": false, "label": SERVICE_LABEL }),
    ))
}

/// Start the installed service.
pub fn start() -> std::io::Result<Outcome> {
    let (mgr, _user) = manager()?;
    mgr.start(ServiceStartCtx { label: label()? })?;
    Ok(Outcome::new(
        format!("dig-node: start requested for \"{SERVICE_LABEL}\""),
        json!({ "started": true, "label": SERVICE_LABEL }),
    ))
}

/// Stop the running service.
pub fn stop() -> std::io::Result<Outcome> {
    let (mgr, _user) = manager()?;
    mgr.stop(ServiceStopCtx { label: label()? })?;
    Ok(Outcome::new(
        format!("dig-node: stop requested for \"{SERVICE_LABEL}\""),
        json!({ "stopped": true, "label": SERVICE_LABEL }),
    ))
}

/// Report whether the node is actually serving on the configured port, by probing
/// `GET /health`. This is the meaningful "is it up?" check (the `service-manager`
/// trait exposes no status query), and it works the same whether the node runs as
/// an installed service or a manual `run`.
///
/// Returns an [`Outcome`] whose `result.serving` boolean is the answer; the caller
/// maps `serving:false` to a non-zero exit so scripts can gate on it.
pub fn status(config: &Config) -> std::io::Result<Outcome> {
    let addr = config.bind_addr();
    let url = format!("http://{addr}/health");
    // A tiny blocking probe with a std TcpStream + manual HTTP keeps `status` free
    // of an async runtime and an HTTP client dependency in the binary path. A
    // 2-second connect/read timeout is plenty for loopback.
    let (serving, summary) = match probe_health(&addr) {
        Ok(true) => (true, format!("dig-node: SERVING on http://{addr} ({url})")),
        Ok(false) => (
            false,
            format!(
                "dig-node: NOT responding on http://{addr} \
                 (the service may be stopped or not installed)"
            ),
        ),
        Err(e) => (
            false,
            format!("dig-node: could not probe http://{addr}: {e}"),
        ),
    };
    Ok(Outcome::new(
        summary,
        json!({ "serving": serving, "addr": addr, "health_url": url }),
    ))
}

/// Minimal blocking HTTP/1.0 `GET /health` probe over loopback. Returns whether
/// the response status line is `2xx`. Avoids pulling an async HTTP client into the
/// status path. `addr` is `host:port`.
fn probe_health(addr: &str) -> std::io::Result<bool> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let mut stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        // Connection refused / unreachable → not serving (not a hard error).
        Err(_) => return Ok(false),
    };
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = format!("GET /health HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    let mut buf = Vec::with_capacity(256);
    // Read just enough for the status line.
    let mut chunk = [0u8; 256];
    if let Ok(n) = stream.read(&mut chunk) {
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    Ok(is_2xx_status_line(&head))
}

/// Is the first line of an HTTP response a `2xx` status line? PURE — parses only
/// the status line (`HTTP/x.y CODE ...`), so an unrelated `2` elsewhere in the
/// response (e.g. a `Date: ... 2026` header) can never be mistaken for success.
fn is_2xx_status_line(response_head: &str) -> bool {
    let first = response_head.lines().next().unwrap_or("");
    if !first.starts_with("HTTP/") {
        return false;
    }
    // Status line: "HTTP/1.1 200 OK" — the code is the 2nd whitespace token.
    first
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .map(|code| (200..300).contains(&code))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_label_parses() {
        let l = label().expect("constant label must parse");
        assert_eq!(l.application, "dig-node");
    }

    #[test]
    fn service_label_qualified_name_matches_the_constant() {
        // `configure_windows_recovery` targets `sc.exe failure` at
        // `svc_label.to_qualified_name()` — this MUST be the exact name
        // `mgr.install` registered the service under (SERVICE_LABEL itself, for
        // this 3-segment reverse-DNS label), or the recovery-action call would
        // silently target a nonexistent service.
        let l = label().expect("constant label must parse");
        assert_eq!(l.to_qualified_name(), SERVICE_LABEL);
    }

    #[test]
    fn recovery_action_args_build_the_expected_sc_failure_command() {
        let args = recovery_action_args(SERVICE_LABEL);
        assert_eq!(
            args,
            vec![
                "failure".to_string(),
                SERVICE_LABEL.to_string(),
                "reset=".to_string(),
                "86400".to_string(),
                "actions=".to_string(),
                "restart/5000/restart/10000/restart/30000".to_string(),
            ]
        );
    }

    #[test]
    fn recovery_action_args_targets_the_given_service_name() {
        // Pure builder — must plumb an arbitrary service name through unchanged,
        // not hardcode SERVICE_LABEL internally.
        let args = recovery_action_args("some.other.service");
        assert_eq!(args[1], "some.other.service");
    }

    #[test]
    fn status_reports_false_when_nothing_listens() {
        // Probe a port nothing is bound to → not serving, no error.
        let cfg = Config {
            port: 1, // privileged + unbound in this test context → connect refused
            ..Config::default()
        };
        let outcome = status(&cfg).expect("status never hard-errors on a closed port");
        assert_eq!(outcome.result["serving"], serde_json::json!(false));
    }

    #[test]
    fn probe_health_false_on_refused_connection() {
        // 127.0.0.1:1 has nothing listening in the test environment.
        assert!(!probe_health("127.0.0.1:1").unwrap());
    }

    #[test]
    fn is_2xx_status_line_parses_the_code_not_stray_digits() {
        assert!(is_2xx_status_line("HTTP/1.1 200 OK\r\nDate: x\r\n"));
        assert!(is_2xx_status_line("HTTP/1.0 204 No Content"));
        // A 404 whose Date header contains a "2" (e.g. year 2026) must NOT pass —
        // the regression that motivated parsing the status code, not substring " 2".
        assert!(!is_2xx_status_line(
            "HTTP/1.0 404 Not Found\r\nDate: Sat, 27 Jun 2026 00:00:00 GMT\r\n"
        ));
        assert!(!is_2xx_status_line("HTTP/1.1 500 Internal Server Error"));
        assert!(!is_2xx_status_line("garbage"));
        assert!(!is_2xx_status_line(""));
    }
}
