//! OS-service registration for dig-node, across Windows (SCM), Linux
//! (systemd) and macOS (launchd) via the `service-manager` crate.
//!
//! The whole point of the Rust rewrite: a self-contained binary that installs
//! cleanly as an OS service, with no Node runtime to depend on. `install` registers
//! `dig-node run` to auto-start and serve on the loopback port; `uninstall`
//! removes it; `start`/`stop` control the registered service; `status` reports
//! whether it is registered and actually serving.
//!
//! This module owns the service IDENTITY and the **clean-reinstall** contract
//! (mirrors the sibling `dig-dns` service module):
//!
//! * **Service id** — [`SERVICE_LABEL`] `net.dignetwork.dig-node`, the reverse-DNS name used
//!   verbatim as the Windows SCM service name (`sc create`/`query`/`start`/`stop`/`delete`) and
//!   the launchd plist label — `ServiceLabel::to_qualified_name()`. On **systemd** the actual
//!   registered unit name is DIFFERENT: `service-manager`'s systemd backend derives it from
//!   `to_script_name()` instead (`dignetwork-dig-node`, dropping the `net` qualifier) — see
//!   [`os_native_service_name`], which a real 3-OS CI run proved MUST be used for any direct
//!   existence probe (getting this wrong silently defeats clean-reinstall on Linux, #494).
//!   Distinct from [`crate::meta::SERVICE_NAME`] (`"dig-node"`, the RPC/build-info identity) —
//!   the two never need to agree.
//! * **Display name** — [`SERVICE_DISPLAY_NAME`] "DIG NETWORK: NODE", the human-friendly name
//!   shown in the Windows Services console (set with `sc config … displayname=` after create,
//!   because `service-manager` 0.7's `sc create` hardcodes the display name to the service id —
//!   see [`SystemServiceBackend::create`]), then read back with `sc qc` to verify the override
//!   actually took (see [`query_windows_display_name`]). The native macOS/Linux packages
//!   (`packaging/macos`, `packaging/linux`) carry the same friendly name via their own static
//!   unit files (the systemd unit's `Description=`; launchd has no equivalent display-name key,
//!   so the plist's `Label` — already `net.dignetwork.dig-node` — is the only OS-visible name).
//! * **Clean-reinstall** — [`reinstall`]: if the service ALREADY EXISTS, **stop → delete
//!   (deregister) → wait for removal → (re)create** — a clean recreate, never a
//!   reconfigure-in-place. This is what avoids Windows `CreateService 1073 "the specified
//!   service already exists"` on a re-run of `dig-node install`.
//!
//!   **`install` never auto-starts** (deliberately unlike `dig-dns`'s equivalent): the
//!   dig-installer's `register_dig_node` step calls `dig-node install` and then, when
//!   configured to start it, a SEPARATE `dig-node start` — and treats a `start` failure as a
//!   hard error for that step. If `install` also started the service, that second `start` would
//!   hit "service already running" (SCM 1056 / a systemd/launchd no-op-or-error depending on
//!   backend) and could flip the installer's reported `installed` status to `false` even though
//!   the service is up. So `reinstall` here stops at **create** — a caller starts it explicitly.
//!
//! Install level by platform:
//!   * Linux (systemd) / macOS (launchd) — **user-level** by default (`--user` /
//!     `gui` domain), so no root/sudo is needed and the service runs as the
//!     installing user.
//!   * Windows (SCM) — **system-level only**: the Service Control Manager has no
//!     per-user services, so `install`/`uninstall` require an **elevated
//!     (Administrator)** console. This is detected up front and reported with a
//!     clear message rather than failing deep inside `sc.exe`.
//!
//! The OS calls are behind the [`ServiceBackend`] trait so the clean-reinstall ORDER is
//! unit-tested against a recording mock — CI never shells out to `sc`/`launchctl`/`systemctl`
//! for that part; a real 3-OS install/uninstall round-trip is exercised by the
//! `service-smoke` CI job (`.github/workflows/service-smoke.yml`).

use std::cell::Cell;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

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

/// The human-friendly display name shown in the Windows Services console. On launchd/systemd
/// the service id IS the visible name (systemd's own `Description=` carries the friendly text
/// on the native `.deb`/`.pkg` install — see the module doc), so this constant is primarily a
/// Windows-facing label.
pub const SERVICE_DISPLAY_NAME: &str = "DIG NETWORK: NODE";

/// How many times [`reinstall`] polls for a deleted service to disappear before giving up. A
/// Windows service marked for deletion (`sc delete`) can linger until its open handles close;
/// `40 × 500ms = 20s` is generous for a loopback node with no long-lived clients.
const REMOVAL_POLL_ATTEMPTS: u32 = 40;

/// The interval between removal polls (see [`REMOVAL_POLL_ATTEMPTS`]).
const REMOVAL_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Whether user-level (no-elevation) install is supported on this OS. Windows SCM
/// is system-only; systemd/launchd support a user domain.
#[cfg(windows)]
const PREFERS_USER_LEVEL: bool = false;
#[cfg(not(windows))]
const PREFERS_USER_LEVEL: bool = true;

// These recovery-action items back the Windows-only crash-restart path
// ([`configure_windows_recovery`] + the note in [`install`]), but are deliberately kept
// platform-INDEPENDENT so the pure argument-building is unit-tested on EVERY CI runner (the
// coverage/test job runs on Linux). Their only non-test consumer is `#[cfg(windows)]`, so off
// Windows a non-test build sees them as unused — silence that one targeted case rather than
// gate them (which would drop the Linux CI coverage of the builder).

/// `sc.exe failure` recovery-action config: reset the failure counter after one
/// day of no further crashes, and restart the service 5s/10s/30s after the
/// 1st/2nd/subsequent failure in that window. Mirrors the spirit of systemd's
/// `Restart=on-failure` default (which `service-manager` already applies on
/// Linux) and launchd's `KeepAlive` (already applied on macOS) — see
/// [`configure_windows_recovery`].
#[cfg_attr(not(windows), allow(dead_code))]
const RECOVERY_RESET_SECONDS: &str = "86400";
#[cfg_attr(not(windows), allow(dead_code))]
const RECOVERY_ACTIONS: &str = "restart/5000/restart/10000/restart/30000";

/// Build the `sc.exe failure` argument list that configures restart-on-crash
/// recovery actions for `service_name`. PURE (no process spawn) so the argument
/// construction is unit-testable without invoking `sc.exe` for real.
#[cfg_attr(not(windows), allow(dead_code))]
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
/// (§`SystemServiceBackend::create`) — it never configures `SERVICE_CONFIG_FAILURE_ACTIONS`,
/// and the pinned `windows-service` 0.7 crate exposes no `ChangeServiceConfig2` binding
/// either, so Windows services do NOT restart on crash unless this is set
/// explicitly (unlike systemd/launchd, which `service-manager` already covers by
/// default). Call ONLY after a successful [`reinstall`]; the caller treats a
/// failure here as non-fatal (see [`install`]).
#[cfg(windows)]
fn configure_windows_recovery(service_name: &str) -> io::Result<()> {
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
        Err(io::Error::other(msg))
    }
}

// ---------------------------------------------------------------------------------------------
// The clean-reinstall contract: a pure plan + a backend trait + the stop/delete/wait/create
// orchestration, unit-tested end-to-end with a recording mock (no real OS service involved).
// ---------------------------------------------------------------------------------------------

/// What to register: the service identity + the program the SCM/launchd/systemd runs, plus the
/// environment that reproduces the resolved [`Config`] so the installed service serves
/// identically to a manual `dig-node run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    /// The reverse-DNS service id ([`SERVICE_LABEL`]).
    pub label: String,
    /// The Windows display name ([`SERVICE_DISPLAY_NAME`]).
    pub display_name: String,
    /// Absolute path to the program the service runs (this `dig-node` binary).
    pub program: PathBuf,
    /// Arguments passed to `program` (`run-service` on Windows, else `run`).
    pub args: Vec<OsString>,
    /// Environment variables baked into the service so it resolves the SAME config the
    /// installing invocation did (the service does not inherit the installer's shell env).
    pub environment: Vec<(String, String)>,
    /// Whether the service auto-starts on boot/login (registration flag — distinct from being
    /// started NOW; see the module doc's "`install` never auto-starts" note).
    pub autostart: bool,
}

/// The OS-service backend: the four primitive operations the clean-reinstall composes. Behind a
/// trait so [`reinstall`]'s ORDER (stop → delete → wait → create) is unit-tested with a
/// recording mock and CI never registers a real service. The real implementation is
/// [`SystemServiceBackend`].
pub trait ServiceBackend {
    /// Is the service currently registered with the OS service manager?
    fn is_installed(&self) -> io::Result<bool>;
    /// Stop the running service (best-effort at the call site: a not-running service is not an
    /// error the caller must fail on).
    fn stop(&self) -> io::Result<()>;
    /// Deregister (delete) the service from the OS service manager.
    fn delete(&self) -> io::Result<()>;
    /// Register (create) the service from `plan`, including the display name on Windows.
    fn create(&self, plan: &InstallPlan) -> io::Result<()>;
}

/// What [`reinstall`] did, for machine-readable + human output. `existed` records whether a
/// prior registration was found (⇒ the stop/delete/wait clean-recreate ran); a fresh install
/// leaves `existed`/`stopped`/`deleted` false.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReinstallReport {
    /// A prior registration existed, so the clean-recreate path ran.
    pub existed: bool,
    /// The existing service was stopped before deletion.
    pub stopped: bool,
    /// The existing service was deleted (deregistered).
    pub deleted: bool,
    /// The service was (re)created.
    pub created: bool,
}

/// **Clean-reinstall.** If the service ALREADY EXISTS: stop it (best-effort), delete
/// (deregister) it, wait for the removal to take effect, THEN (re)create it with the display
/// name — a clean recreate, NEVER a reconfigure-in-place. When no prior registration exists it
/// simply creates. Deliberately does NOT start the service either way — see the module doc.
///
/// This ordering is the fix for Windows `CreateService 1073 "the specified service already
/// exists"`: by deleting before creating, `create` never targets an existing service.
pub fn reinstall<B: ServiceBackend>(
    backend: &B,
    plan: &InstallPlan,
) -> io::Result<ReinstallReport> {
    let mut report = ReinstallReport::default();

    if backend.is_installed()? {
        report.existed = true;
        // Stop is best-effort: a registered-but-already-stopped service errors on stop, and
        // that must not block the delete + recreate that follows.
        if backend.stop().is_ok() {
            report.stopped = true;
        }
        backend.delete()?;
        report.deleted = true;
        wait_for_removal(backend)?;
    }

    backend.create(plan)?;
    report.created = true;
    Ok(report)
}

/// Poll [`ServiceBackend::is_installed`] until the service is gone, bounded by
/// [`REMOVAL_POLL_ATTEMPTS`]. Checks BEFORE sleeping, so a backend that removes synchronously
/// (the test mock, and systemd/launchd) returns immediately with no delay; only a lingering
/// Windows deletion actually waits. Errors with `TimedOut` if the service is still present
/// after the window, so a caller never blindly recreates onto a still-existing service (1073).
fn wait_for_removal<B: ServiceBackend>(backend: &B) -> io::Result<()> {
    for _ in 0..REMOVAL_POLL_ATTEMPTS {
        if !backend.is_installed()? {
            return Ok(());
        }
        std::thread::sleep(REMOVAL_POLL_INTERVAL);
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "dig-node: service \"{SERVICE_LABEL}\" was deleted but is still present after \
             waiting for removal; cannot cleanly recreate it (a handle may be held open — \
             close the Services console and retry)"
        ),
    ))
}

/// Build the [`InstallPlan`] for `program` from a resolved [`Config`]. PURE (given the program
/// path), so the identity + args + baked environment are unit-tested without touching the OS.
/// The installed service runs `run-service` on Windows (the SCM protocol entrypoint) and `run`
/// elsewhere (systemd/launchd exec the foreground process directly).
pub fn build_plan(config: &Config, program: PathBuf) -> InstallPlan {
    let entry_arg = if cfg!(windows) { "run-service" } else { "run" };

    // Bake the resolved config into the service environment so it serves identically to the
    // invocation that installed it (a service does not inherit the installing shell's env).
    let mut environment = vec![
        ("DIG_NODE_PORT".to_string(), config.port.to_string()),
        ("DIG_RPC_UPSTREAM".to_string(), config.upstream.clone()),
        // Mark the installed service as a SERVICE run (#501): the running daemon may bootstrap
        // the machine-wide state dir when absent, whereas a bare CLI never does. On Windows this
        // is belt-and-suspenders (the SCM `run-service` entrypoint also sets it); on
        // systemd/launchd this env carries the signal into the unit.
        (
            crate::state::RUN_CONTEXT_ENV.to_string(),
            crate::state::RUN_CONTEXT_SERVICE.to_string(),
        ),
    ];
    // Only record DIG_NODE_HOST when the operator gave an EXPLICIT override
    // (#288): omitting it lets the installed service resolve the same default the
    // CLI would — bind BOTH loopback families (127.0.0.1 AND [::1], §5.2) —
    // instead of freezing today's IPv4-only default into the service's
    // environment forever. An operator who set DIG_NODE_HOST before `dig-node
    // install` still gets that exact override carried into the service.
    if let Some(host) = config.host {
        environment.push(("DIG_NODE_HOST".to_string(), host.to_string()));
    }
    // Only record DIG_NODE_CACHE when an explicit dir was set: omitting it lets the
    // service resolve dig-node's shared canonical default — the SAME dir the DIG
    // Browser's in-process node uses — so the two share ONE cache (#96). Recording
    // a path here pins the service to it, so an operator pointing the service at a
    // dedicated cache must set the SAME path for the browser to keep sharing.
    if let Some(dir) = crate::config::cache_dir_env_value(config.cache_dir.as_deref()) {
        environment.push(("DIG_NODE_CACHE".to_string(), dir));
    }

    InstallPlan {
        label: SERVICE_LABEL.to_string(),
        display_name: SERVICE_DISPLAY_NAME.to_string(),
        program,
        args: vec![OsString::from(entry_arg)],
        environment,
        autostart: true,
    }
}

/// Build the `sc.exe config <name> displayname= "<display>"` argument list that overrides the
/// Windows service display name after `service-manager`'s `sc create` (which sets it to the
/// service id). PURE (no process spawn) so the argument construction is unit-testable without
/// invoking `sc.exe`.
#[cfg_attr(not(windows), allow(dead_code))]
fn display_name_config_args(service_name: &str, display_name: &str) -> Vec<String> {
    vec![
        "config".to_string(),
        service_name.to_string(),
        "displayname=".to_string(),
        display_name.to_string(),
    ]
}

/// Parse the `DISPLAY_NAME` field out of `sc.exe qc <name>` output (the read-back verify for
/// [`SystemServiceBackend::create`]'s display-name override). PURE (no process spawn) so the
/// parsing is unit-tested without invoking `sc.exe`. Typical `sc qc` output:
///
/// ```text
/// SERVICE_NAME: net.dignetwork.dig-node
///         TYPE               : 10  WIN32_OWN_PROCESS
///         ...
///         DISPLAY_NAME       : DIG NETWORK: NODE
/// ```
///
/// Splits on the FIRST `:` only, so a display name that itself contains a colon (this one does:
/// "DIG NETWORK: NODE") is not truncated.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_sc_qc_display_name(output: &str) -> Option<&str> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case("DISPLAY_NAME")
            .then(|| value.trim())
    })
}

// ---------------------------------------------------------------------------------------------
// The real, OS-backed backend + the CLI-facing install/uninstall/start/stop/status commands.
// ---------------------------------------------------------------------------------------------

/// Build the parsed service label (infallible for our constant, but the crate
/// returns a Result, so surface a clear error if the constant is ever mis-edited).
fn label() -> io::Result<ServiceLabel> {
    ServiceLabel::from_str(SERVICE_LABEL)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// Absolute path to the currently-running `dig-node` executable, so the
/// installed service points at THIS binary (not a PATH lookup that might resolve
/// to a different/absent copy).
fn current_exe() -> io::Result<PathBuf> {
    std::env::current_exe()
}

/// The opt-in escape hatch that bypasses the §565 privileged-target gate
/// ([`ensure_service_target_is_safe`]). Set to a truthy value ONLY for a controlled test/dev
/// install of an unreleased build from a build directory (e.g. the `service-smoke` CI job installs
/// `target/release/dig-node` from the runner's user-writable checkout). It is default-OFF and MUST
/// NOT be set on an end-user machine — the canonical install (native OS package, §9.7) always lands
/// the binary in a protected admin-owned directory and never needs it.
const ALLOW_INSECURE_SERVICE_TARGET_ENV: &str = "DIG_NODE_ALLOW_INSECURE_SERVICE_TARGET";

/// Whether [`ALLOW_INSECURE_SERVICE_TARGET_ENV`] is set to a truthy value (`1`/`true`/`yes`,
/// case-insensitive). Any other value — or an unset var — leaves the gate ENABLED (default-safe).
fn insecure_service_target_allowed() -> bool {
    std::env::var(ALLOW_INSECURE_SERVICE_TARGET_ENV)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

/// Refuse to register a PRIVILEGED (system-level) service whose program binary lives in a
/// user-writable directory — the §565 privilege-escalation class.
///
/// A system-level service runs as a privileged principal (Windows LocalSystem / a root daemon).
/// If its recorded `ExecStart` / SCM `binPath` / launchd `ProgramArguments` points at a binary a
/// non-privileged user can replace, that user gains PERSISTENT privileged code execution: swap the
/// file, wait for the next service start, and the swapped code runs as SYSTEM/root. So before
/// registering a system-level service, its program's directory MUST be privileged-owned
/// (root/SYSTEM, no group/world write) — verified through the SAME spawn-free owner gate the
/// self-heal spawn root (#565) and the TLS material root (#661) use ([`crate::security`]), so the
/// three never drift. Fails CLOSED: an indeterminate owner is refused.
///
/// A **user-level** install (Linux systemd / macOS launchd, the default there) runs as the very
/// user who owns the binary — there is no privilege boundary to cross — so it is always allowed.
/// `allow_insecure_override` is the explicit test/dev opt-out
/// ([`ALLOW_INSECURE_SERVICE_TARGET_ENV`]); it is default-`false` in production.
fn ensure_service_target_is_safe(
    program: &std::path::Path,
    user_level: bool,
    allow_insecure_override: bool,
) -> io::Result<()> {
    // A user-level service runs as the installing user: swapping a binary that user already owns
    // grants that user nothing it lacked. No privilege boundary, no LPE — always allowed.
    if user_level {
        return Ok(());
    }
    // The program's directory is the surface an attacker would need write access to; a
    // privileged-owned directory keeps a non-privileged user from replacing the binary in it.
    let root = program.parent().unwrap_or(program);
    if crate::security::dir_is_privileged(root) {
        return Ok(());
    }
    // Explicit, default-off test/dev opt-out — a controlled install of an unreleased build from a
    // build directory (see the env-var doc). Never set on an end-user machine.
    if allow_insecure_override {
        eprintln!(
            "dig-node: WARN {ALLOW_INSECURE_SERVICE_TARGET_ENV} is set — registering a \
             system-level service pointing at \"{}\", a user-writable directory. This is a \
             privilege-escalation risk (#565) and is intended ONLY for test/dev installs of an \
             unreleased build.",
            program.display()
        );
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "dig-node: refusing to register a system-level (privileged) service pointing at \
             \"{}\", whose directory is writable by a non-privileged user. Registering it would \
             let any local user replace that binary and gain persistent SYSTEM/root code \
             execution (a privilege-escalation vector, #565). Install dig-node into a protected, \
             admin-owned location — via the DIG installer or a native OS package — and re-run \
             `dig-node install` from there.",
            program.display()
        ),
    ))
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

/// The real [`ServiceBackend`]: the native OS service manager (user-level on Linux/macOS,
/// system-level on Windows) plus the OS existence probe and the Windows display-name override
/// + read-back verify.
pub struct SystemServiceBackend {
    label: ServiceLabel,
    manager: Box<dyn ServiceManager>,
    /// Whether the manager is operating at user level (Linux/macOS) — surfaced for messaging.
    user_level: bool,
    /// Windows-only: whether the post-create `sc qc` read-back confirmed the display name was
    /// actually applied. `None` off Windows (nothing to verify) or before a `create` has run.
    display_name_verified: Cell<Option<bool>>,
}

impl SystemServiceBackend {
    /// Acquire the native service manager, set to user-level where the platform supports it.
    pub fn new() -> io::Result<Self> {
        let mut manager = <dyn ServiceManager>::native()?;
        let mut user_level = false;
        if PREFERS_USER_LEVEL && manager.set_level(ServiceLevel::User).is_ok() {
            user_level = true;
        }
        Ok(Self {
            label: label()?,
            manager,
            user_level,
            display_name_verified: Cell::new(None),
        })
    }

    /// Whether this backend installs at user level (no elevation) vs system level.
    pub fn user_level(&self) -> bool {
        self.user_level
    }

    /// Windows: whether the `sc qc` read-back confirmed the display-name override took effect.
    /// `None` off Windows, or if [`ServiceBackend::create`] has not run yet.
    pub fn display_name_verified(&self) -> Option<bool> {
        self.display_name_verified.get()
    }

    /// Start the registered service.
    fn start(&self) -> io::Result<()> {
        self.manager.start(ServiceStartCtx {
            label: self.label.clone(),
        })
    }
}

impl ServiceBackend for SystemServiceBackend {
    fn is_installed(&self) -> io::Result<bool> {
        Ok(query_installed(&os_native_service_name(&self.label)))
    }

    fn stop(&self) -> io::Result<()> {
        self.manager.stop(ServiceStopCtx {
            label: self.label.clone(),
        })
    }

    fn delete(&self) -> io::Result<()> {
        self.manager.uninstall(ServiceUninstallCtx {
            label: self.label.clone(),
        })
    }

    fn create(&self, plan: &InstallPlan) -> io::Result<()> {
        self.manager.install(ServiceInstallCtx {
            label: self.label.clone(),
            program: plan.program.clone(),
            args: plan.args.clone(),
            contents: None,
            username: None,
            working_directory: None,
            environment: Some(plan.environment.clone()),
            autostart: plan.autostart,
        })?;
        // service-manager's `sc create` sets the display name to the service id; override it
        // with the human-friendly name, then read it back with `sc qc` to confirm the override
        // actually took (rather than trusting a silent `sc config` exit code). Both steps are
        // best-effort: a failure leaves the service installed + working, just showing the id
        // (or an unconfirmed display) in the Services console.
        #[cfg(windows)]
        {
            let qualified = self.label.to_qualified_name();
            set_windows_display_name(&qualified, &plan.display_name);
            let verified = query_windows_display_name(&qualified)
                .ok()
                .flatten()
                .is_some_and(|actual| actual == plan.display_name);
            self.display_name_verified.set(Some(verified));
        }
        Ok(())
    }
}

/// The identifier [`query_installed`] must probe the OS with — the SAME identifier
/// `service-manager`'s own backend registers the service under, which is **NOT uniformly
/// [`ServiceLabel::to_qualified_name`]**: `service-manager`'s Windows (`sc.rs`) and launchd
/// (`launchd.rs`) backends register under `to_qualified_name()` (the reverse-DNS
/// `net.dignetwork.dig-node`), but its **systemd** backend (`systemd.rs`) derives the unit file
/// name from `to_script_name()` instead — `{organization}-{application}` (`dignetwork-dig-node`,
/// dropping the `net` qualifier entirely). Probing systemd with the qualified name looks for a
/// unit that never exists, so `is_installed` always reports `false` there, silently defeating
/// the whole clean-reinstall contract (caught by the `service-smoke` CI job on `ubuntu-latest`:
/// the "install a second time" step landed `reinstalled:false` instead of `true`).
fn os_native_service_name(label: &ServiceLabel) -> String {
    if cfg!(all(unix, not(target_os = "macos"))) {
        label.to_script_name()
    } else {
        label.to_qualified_name()
    }
}

/// Probe whether a service named `service_name` is registered, per OS. Best-effort: a probe
/// that cannot run (tool missing) reports `false` so the clean-reinstall proceeds to create.
#[cfg(windows)]
fn query_installed(service_name: &str) -> bool {
    // `sc query <name>` exits 0 when the service exists, 1060 (does-not-exist) otherwise.
    std::process::Command::new("sc.exe")
        .args(["query", service_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// macOS launchd existence probe: `launchctl print <domain>/<label>` exits 0 when the service
/// is bootstrapped.
#[cfg(target_os = "macos")]
fn query_installed(service_name: &str) -> bool {
    let domain = launchd_domain_target(service_name);
    std::process::Command::new("launchctl")
        .args(["print", &domain])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Linux systemd existence probe: `systemctl [--user] cat <label>.service` exits 0 when the
/// unit file exists (non-zero "No files found" otherwise).
#[cfg(all(unix, not(target_os = "macos")))]
fn query_installed(service_name: &str) -> bool {
    let unit = format!("{service_name}.service");
    let mut cmd = std::process::Command::new("systemctl");
    if PREFERS_USER_LEVEL {
        cmd.arg("--user");
    }
    cmd.args(["cat", &unit])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The launchd domain target (`gui/<uid>/<label>` for a user agent, `system/<label>` for a
/// daemon) `launchctl print` addresses. PURE given the uid, so the format is testable.
#[cfg(target_os = "macos")]
fn launchd_domain_target(service_name: &str) -> String {
    if PREFERS_USER_LEVEL {
        format!("gui/{}/{}", unsafe { libc_getuid() }, service_name)
    } else {
        format!("system/{service_name}")
    }
}

#[cfg(target_os = "macos")]
fn libc_getuid() -> u32 {
    // Avoid a `libc` dependency for one call: read the effective uid via `id -u`.
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Override the Windows service display name (`sc config <name> displayname= "<display>"`).
/// Best-effort; a failure is swallowed (the service is already usable under its id) — the
/// caller reads back the result via [`query_windows_display_name`].
#[cfg(windows)]
fn set_windows_display_name(service_name: &str, display_name: &str) {
    let args = display_name_config_args(service_name, display_name);
    let _ = std::process::Command::new("sc.exe")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Read back the Windows service's CURRENT display name via `sc qc <name>`, so
/// [`SystemServiceBackend::create`] can confirm the `sc config displayname=` override actually
/// took effect rather than trusting its exit code alone.
#[cfg(windows)]
fn query_windows_display_name(service_name: &str) -> io::Result<Option<String>> {
    let output = std::process::Command::new("sc.exe")
        .args(["qc", service_name])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_sc_qc_display_name(&stdout).map(str::to_string))
}

/// Install dig-node as an auto-starting OS service that runs `dig-node run` on the configured
/// loopback port, via the clean-reinstall contract (stop → delete → recreate on an existing
/// service; create otherwise — see the module doc for why this never auto-starts). On Windows,
/// also configures SCM recovery actions (restart-on-crash) — see
/// [`configure_windows_recovery`] — so a crashed service comes back up the same way systemd
/// (`Restart=on-failure`) and launchd (`KeepAlive`) already do for Linux/macOS via
/// `service-manager`'s own defaults.
pub fn install(config: &Config) -> io::Result<Outcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dig-node: installing a Windows service requires an elevated \
             (Administrator) console. Re-run this in a terminal opened with \
             \"Run as administrator\".",
        ));
    }

    let backend = SystemServiceBackend::new()?;
    let program = current_exe()?;
    // §565 LPE gate: before touching anything, refuse a privileged (system-level) registration
    // whose program binary sits in a user-writable directory — a swapped binary would run as
    // SYSTEM/root on the next start. Checked FIRST so a refusal has no side effects (no state-dir
    // harden, no service create). A user-level install runs as the invoking user and is allowed.
    ensure_service_target_is_safe(
        &program,
        backend.user_level(),
        insecure_service_target_allowed(),
    )?;
    let plan = build_plan(config, program.clone());

    // HARDEN the machine-wide state dir NOW, as the INSTALLING (interactive) user, per the
    // #501 contract: owner→SYSTEM, purge foreign ACEs, protected DACL granting SYSTEM +
    // Administrators full AND this interactive user READ, then readback-verify. Setting the
    // owner to SYSTEM here means the LocalSystem service's own startup harden later sees a
    // TRUSTED dir and PRESERVES this interactive read grant (rather than purging it), so the
    // operator's `dig-node pair` can read the token the service writes. Best-effort + cross-
    // platform: on a user-level Linux/macOS install the daemon runs as the SAME user, so the
    // legacy per-user fallback already keeps daemon + CLI in agreement, and a failure to
    // create/secure `/var/lib/dig-node` (needs root) is expected — the service re-secures it
    // at startup regardless.
    if let Some(machine_dir) = crate::state::machine_state_dirs().into_iter().next() {
        let grant = crate::state::interactive_read_grant();
        if let Err(e) = crate::state::harden_state_dir(&machine_dir, grant.as_deref()) {
            eprintln!(
                "dig-node: WARN could not harden {} during install ({e}); the service will \
                 re-secure it at startup",
                machine_dir.display()
            );
        }
    }

    let report = reinstall(&backend, &plan)?;

    // Windows: best-effort SCM recovery-action config. A failure here (e.g.
    // `sc.exe` missing/blocked) must not fail the whole install — the service is
    // already registered and usable, just without auto-restart-on-crash; surface
    // it as a note instead. Linux/macOS need no equivalent step: service-manager's
    // own defaults (`Restart=on-failure` / `KeepAlive`) already cover them.
    #[cfg(windows)]
    let (recovery_configured, recovery_note) = match configure_windows_recovery(SERVICE_LABEL) {
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

    let scope = if backend.user_level() {
        "user"
    } else {
        "system"
    };
    let action = if report.existed {
        "reinstalled (stopped + deleted the existing service, then recreated it)"
    } else {
        "installed"
    };
    let addr = config.bind_addr();
    let mut summary = format!(
        "dig-node: {action} as a {scope}-level service\n  \
         id:      {SERVICE_LABEL}\n  \
         display: {SERVICE_DISPLAY_NAME}\n  \
         program: {}\n  serves:  http://{addr}\n  Set the DIG Chrome extension's \"server host\" to {addr}.\n  \
         Start it now with: dig-node start",
        program.display(),
    );
    if let Some(note) = &recovery_note {
        summary.push_str("\n  ");
        summary.push_str(note);
    }
    let display_name_verified = backend.display_name_verified();
    if display_name_verified == Some(false) {
        summary.push_str(
            "\n  note: the Windows display name override could not be confirmed via `sc qc`; \
             the service is installed and usable, just possibly showing its id in the \
             Services console.",
        );
    }
    let mut result = json!({
        "installed": true,
        "reinstalled": report.existed,
        "registered": true,
        "started": false,
        "label": SERVICE_LABEL,
        "display_name": SERVICE_DISPLAY_NAME,
        "scope": scope,
        "program": program.display().to_string(),
        "addr": addr,
        "upstream": config.upstream,
        "recovery_configured": recovery_configured,
    });
    if let Some(verified) = display_name_verified {
        result["display_name_verified"] = json!(verified);
    }
    Ok(Outcome::new(summary, result))
}

/// Uninstall the dig-node service. Stops it first (best-effort) so the uninstall
/// is clean.
pub fn uninstall() -> io::Result<Outcome> {
    if cfg!(windows) && !is_elevated() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dig-node: uninstalling a Windows service requires an elevated \
             (Administrator) console.",
        ));
    }
    let backend = SystemServiceBackend::new()?;
    // Best-effort stop before removal (ignore "not running" errors).
    let _ = backend.stop();
    backend.delete()?;
    Ok(Outcome::new(
        format!("dig-node: uninstalled service \"{SERVICE_LABEL}\""),
        json!({ "installed": false, "registered": false, "label": SERVICE_LABEL }),
    ))
}

/// Whether an OS service-start error actually means "the service is ALREADY running".
///
/// A `start` on an already-running service is not a failure — it is the desired end state, so
/// `dig-node start` treats it as success (idempotent, #772). Each OS signals it differently and
/// only in the error TEXT (the `service-manager` backend surfaces the tool's stdout/stderr as the
/// `io::Error` message), so this matches the per-OS signatures, case-insensitively:
///
/// * **Windows SCM** — `sc start` exits non-zero with `[SC] StartService FAILED 1056: An instance
///   of the service is already running.` (error 1056). The 1056 code must appear alongside
///   "already" or "running" to avoid false-positives on unrelated errors containing "1056" in a path/PID.
/// * **macOS launchd** — `launchctl load` of a loaded service → `service already loaded` /
///   `Operation already in progress`.
/// * **Linux systemd** — `systemctl start` of an active unit is normally a silent no-op (exit 0),
///   but `already active` is matched for completeness.
///
/// PURE, so the idempotency contract is unit-tested without a real OS service.
pub fn is_already_running_error(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    (m.contains("1056") && (m.contains("already") || m.contains("running")))
        || m.contains("already running")
        || m.contains("already loaded")
        || m.contains("already in progress")
        || m.contains("already active")
}

/// Map an OS `start` result to the CLI [`Outcome`], applying the idempotency rule (#772): a
/// genuine start and an already-running service both report success (exit 0), distinguished by
/// the `already_running` field; any other error propagates. PURE (given the backend result), so
/// the mapping is unit-tested directly.
fn start_outcome(result: io::Result<()>) -> io::Result<Outcome> {
    match result {
        Ok(()) => Ok(Outcome::new(
            format!("dig-node: start requested for \"{SERVICE_LABEL}\""),
            json!({ "started": true, "already_running": false, "label": SERVICE_LABEL }),
        )),
        Err(e) if is_already_running_error(&e.to_string()) => Ok(Outcome::new(
            format!("dig-node: service \"{SERVICE_LABEL}\" is already running"),
            json!({ "started": true, "already_running": true, "label": SERVICE_LABEL }),
        )),
        Err(e) => Err(e),
    }
}

/// Start the installed service. Idempotent: an already-running service is reported as success
/// (#772), never a hard error.
pub fn start() -> io::Result<Outcome> {
    let backend = SystemServiceBackend::new()?;
    start_outcome(backend.start())
}

/// Stop the running service.
pub fn stop() -> io::Result<Outcome> {
    let backend = SystemServiceBackend::new()?;
    backend.stop()?;
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
pub fn status(config: &Config) -> io::Result<Outcome> {
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
fn probe_health(addr: &str) -> io::Result<bool> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

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
    use std::cell::RefCell;

    // -- identity + pure builders -----------------------------------------------------------

    #[test]
    fn service_identity_constants_are_the_canonical_values() {
        assert_eq!(SERVICE_LABEL, "net.dignetwork.dig-node");
        assert_eq!(SERVICE_DISPLAY_NAME, "DIG NETWORK: NODE");
    }

    #[test]
    fn service_label_parses() {
        let l = label().expect("constant label must parse");
        assert_eq!(l.application, "dig-node");
    }

    #[test]
    fn service_label_qualified_name_matches_the_constant() {
        // `configure_windows_recovery` (and the display-name override) target
        // `svc_label.to_qualified_name()` — this MUST be the exact name `mgr.install`
        // registered the service under (SERVICE_LABEL itself, for this 3-segment
        // reverse-DNS label), or those calls would silently target a nonexistent service.
        let l = label().expect("constant label must parse");
        assert_eq!(l.to_qualified_name(), SERVICE_LABEL);
    }

    /// Regression test for #494: a real 3-OS `service-smoke` CI run caught `is_installed`
    /// always reporting `false` on `ubuntu-latest` because it probed under
    /// `to_qualified_name()` ("net.dignetwork.dig-node") when `service-manager`'s systemd
    /// backend actually registers the unit under `to_script_name()`
    /// ("dignetwork-dig-node") — so the clean-reinstall's `existed` check never saw the
    /// service it had just installed, and a second `install` reported `reinstalled:false`
    /// instead of `true`.
    #[test]
    fn os_native_service_name_matches_the_name_service_manager_actually_registers_under() {
        let l = label().expect("constant label must parse");
        let name = os_native_service_name(&l);
        if cfg!(all(unix, not(target_os = "macos"))) {
            // systemd: service-manager's `make_service` names the unit file from
            // `to_script_name()` ("{organization}-{application}"), dropping the `net`
            // qualifier entirely.
            assert_eq!(name, "dignetwork-dig-node");
        } else {
            // Windows SCM (`sc.rs`) and launchd (`launchd.rs`) both register under the
            // reverse-DNS `to_qualified_name()`, i.e. SERVICE_LABEL itself.
            assert_eq!(name, SERVICE_LABEL);
        }
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
    fn display_name_config_args_build_the_sc_config_command() {
        let args = display_name_config_args(SERVICE_LABEL, SERVICE_DISPLAY_NAME);
        assert_eq!(
            args,
            vec![
                "config".to_string(),
                "net.dignetwork.dig-node".to_string(),
                "displayname=".to_string(),
                "DIG NETWORK: NODE".to_string(),
            ]
        );
    }

    #[test]
    fn parse_sc_qc_display_name_reads_the_field_without_truncating_on_its_own_colon() {
        let output = "\
SERVICE_NAME: net.dignetwork.dig-node
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\\dig-node.exe run-service
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : DIG NETWORK: NODE
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
";
        // The display name itself contains a colon ("DIG NETWORK: NODE") — a naive
        // split-on-first-colon-of-the-VALUE would truncate it; this parser splits the
        // LINE on its first colon (the field separator), not the value.
        assert_eq!(parse_sc_qc_display_name(output), Some("DIG NETWORK: NODE"));
    }

    #[test]
    fn parse_sc_qc_display_name_is_none_when_the_field_is_absent() {
        assert_eq!(parse_sc_qc_display_name("SERVICE_NAME: foo\n"), None);
        assert_eq!(parse_sc_qc_display_name(""), None);
    }

    #[test]
    fn build_plan_carries_identity_display_and_baked_config() {
        let config = Config {
            port: 9778,
            upstream: "https://rpc.dig.net".to_string(),
            ..Config::default()
        };
        let plan = build_plan(&config, PathBuf::from("/opt/dig-node"));

        assert_eq!(plan.label, SERVICE_LABEL);
        assert_eq!(plan.display_name, SERVICE_DISPLAY_NAME);
        assert_eq!(plan.program, PathBuf::from("/opt/dig-node"));
        assert!(plan.autostart);
        let env: std::collections::HashMap<_, _> = plan.environment.iter().cloned().collect();
        assert_eq!(env.get("DIG_NODE_PORT").map(String::as_str), Some("9778"));
        assert_eq!(
            env.get("DIG_RPC_UPSTREAM").map(String::as_str),
            Some("https://rpc.dig.net")
        );
        assert_eq!(
            env.get(crate::state::RUN_CONTEXT_ENV).map(String::as_str),
            Some(crate::state::RUN_CONTEXT_SERVICE)
        );
    }

    #[test]
    fn build_plan_omits_host_and_cache_when_no_explicit_override() {
        let plan = build_plan(&Config::default(), PathBuf::from("dig-node"));
        assert!(!plan.environment.iter().any(|(k, _)| k == "DIG_NODE_HOST"));
        assert!(!plan.environment.iter().any(|(k, _)| k == "DIG_NODE_CACHE"));
    }

    #[test]
    fn build_plan_records_an_explicit_host_and_cache_override() {
        let config = Config {
            host: Some(std::net::Ipv4Addr::new(10, 0, 0, 5).into()),
            cache_dir: Some("D:/dig/shared-cache".to_string()),
            ..Config::default()
        };
        let plan = build_plan(&config, PathBuf::from("dig-node"));
        let env: std::collections::HashMap<_, _> = plan.environment.iter().cloned().collect();
        assert_eq!(
            env.get("DIG_NODE_HOST").map(String::as_str),
            Some("10.0.0.5")
        );
        assert_eq!(
            env.get("DIG_NODE_CACHE").map(String::as_str),
            Some("D:/dig/shared-cache")
        );
    }

    #[test]
    fn build_plan_uses_run_service_entry_on_windows_and_run_elsewhere() {
        let plan = build_plan(&Config::default(), PathBuf::from("dig-node"));
        let expected = if cfg!(windows) { "run-service" } else { "run" };
        assert_eq!(plan.args, vec![OsString::from(expected)]);
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

    // -- §565 privileged-install LPE gate (ensure_service_target_is_safe) -------------------

    #[test]
    fn user_level_install_is_always_allowed_regardless_of_binary_owner() {
        // A user-level service runs as the installing user, so a user-writable program dir crosses
        // NO privilege boundary — the gate must not refuse it even from a plainly user-owned dir,
        // and without needing the insecure override.
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("dig-node");
        assert!(
            ensure_service_target_is_safe(&program, /* user_level */ true, false).is_ok(),
            "a user-level install from a user-owned dir must be allowed"
        );
    }

    #[test]
    fn system_level_install_from_a_user_writable_dir_is_refused() {
        // The §565 LPE: a privileged (system-level) service pointing at a binary in a
        // user-writable directory lets any local user swap it for persistent SYSTEM/root exec.
        // A freshly-created tempdir is owned by the (non-privileged) test user — exactly that
        // condition — so registration MUST fail closed with PERMISSION_DENIED.
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("dig-node");
        let err = ensure_service_target_is_safe(&program, /* user_level */ false, false)
            .expect_err("a system-level install from a user-writable dir must be refused");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // The message must name the LPE class + the offending path so an operator can act.
        let msg = err.to_string();
        assert!(msg.contains("#565"), "message cites the LPE class: {msg}");
        assert!(
            msg.contains(&program.display().to_string()),
            "message names the offending program path: {msg}"
        );
    }

    #[test]
    fn insecure_override_permits_a_system_level_install_from_a_user_writable_dir() {
        // The explicit, default-off test/dev opt-out lets a controlled install of an unreleased
        // build proceed from a user-writable build dir (e.g. the service-smoke CI job installing
        // target/release/dig-node). It is default-off, so this branch only opens when set.
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("dig-node");
        assert!(
            ensure_service_target_is_safe(&program, /* user_level */ false, true).is_ok(),
            "the explicit insecure override must permit the otherwise-refused system-level install"
        );
    }

    #[test]
    fn insecure_override_env_parses_only_truthy_values() {
        // The env reader is default-safe: unset or any non-truthy value keeps the gate ENABLED.
        // (Uses process env, so restore it to avoid leaking into sibling tests.)
        let prev = std::env::var(ALLOW_INSECURE_SERVICE_TARGET_ENV).ok();
        for (val, expected) in [
            ("1", true),
            ("true", true),
            ("YES", true),
            ("0", false),
            ("false", false),
            ("", false),
            ("nope", false),
        ] {
            std::env::set_var(ALLOW_INSECURE_SERVICE_TARGET_ENV, val);
            assert_eq!(
                insecure_service_target_allowed(),
                expected,
                "{val:?} must parse to {expected}"
            );
        }
        std::env::remove_var(ALLOW_INSECURE_SERVICE_TARGET_ENV);
        assert!(!insecure_service_target_allowed(), "unset ⇒ gate enabled");
        match prev {
            Some(v) => std::env::set_var(ALLOW_INSECURE_SERVICE_TARGET_ENV, v),
            None => std::env::remove_var(ALLOW_INSECURE_SERVICE_TARGET_ENV),
        }
    }

    // -- the real OS-backed path (no state mutation): probe + status only -------------------

    #[test]
    fn status_reports_false_when_nothing_listens() {
        // Probe a port nothing is bound to → not serving, no error.
        let cfg = Config {
            port: 1, // privileged + unbound in this test context → connect refused
            ..Config::default()
        };
        let outcome = status(&cfg).expect("status never hard-errors on a closed port");
        assert_eq!(outcome.result["serving"], json!(false));
    }

    #[test]
    fn probe_health_false_on_refused_connection() {
        // 127.0.0.1:1 has nothing listening in the test environment.
        assert!(!probe_health("127.0.0.1:1").unwrap());
    }

    #[test]
    fn system_backend_builds_and_probes_an_unregistered_service_cleanly() {
        // Building the native backend + probing for a service that is not registered must never
        // panic and must report a boolean (false in a clean env). No service is created.
        if let Ok(backend) = SystemServiceBackend::new() {
            let _installed = backend.is_installed().expect("probe never hard-errors");
            let _user_level = backend.user_level();
            assert_eq!(backend.display_name_verified(), None, "no create() ran yet");
        }
    }

    // -- clean-reinstall orchestration (the core #494 contract), via a recording mock -------

    /// A recording [`ServiceBackend`] mock. `installed` starts at the given value; `delete`
    /// flips it to `false` (a synchronous removal, like systemd/launchd). `create` SIMULATES
    /// the Windows `CreateService 1073` bug: it FAILS if the service still appears installed —
    /// so a test that recreates onto a live service fails exactly as Windows would, and the
    /// clean-reinstall (which deletes first) is proven to defeat it.
    struct MockBackend {
        installed: RefCell<bool>,
        calls: RefCell<Vec<String>>,
        created_plan: RefCell<Option<InstallPlan>>,
        fail_stop: bool,
    }

    impl MockBackend {
        fn new(installed: bool) -> Self {
            Self {
                installed: RefCell::new(installed),
                calls: RefCell::new(Vec::new()),
                created_plan: RefCell::new(None),
                fail_stop: false,
            }
        }
        fn with_failing_stop(installed: bool) -> Self {
            Self {
                fail_stop: true,
                ..Self::new(installed)
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl ServiceBackend for MockBackend {
        fn is_installed(&self) -> io::Result<bool> {
            self.calls.borrow_mut().push("is_installed".into());
            Ok(*self.installed.borrow())
        }
        fn stop(&self) -> io::Result<()> {
            self.calls.borrow_mut().push("stop".into());
            if self.fail_stop {
                Err(io::Error::other("not running"))
            } else {
                Ok(())
            }
        }
        fn delete(&self) -> io::Result<()> {
            self.calls.borrow_mut().push("delete".into());
            *self.installed.borrow_mut() = false; // synchronous removal
            Ok(())
        }
        fn create(&self, plan: &InstallPlan) -> io::Result<()> {
            self.calls.borrow_mut().push("create".into());
            if *self.installed.borrow() {
                // Reproduce Windows error 1073: cannot create an already-existing service.
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "CreateService 1073: the specified service already exists",
                ));
            }
            *self.created_plan.borrow_mut() = Some(plan.clone());
            *self.installed.borrow_mut() = true;
            Ok(())
        }
    }

    fn plan() -> InstallPlan {
        build_plan(&Config::default(), PathBuf::from("dig-node"))
    }

    #[test]
    fn fresh_install_creates_without_stop_or_delete() {
        let backend = MockBackend::new(false);
        let report = reinstall(&backend, &plan()).expect("fresh install succeeds");

        assert!(!report.existed);
        assert!(report.created);
        assert!(!report.stopped && !report.deleted);
        // No stop/delete on a fresh install; it probes, then creates. Never auto-starts
        // (see the module doc) — `start` is not among the recorded calls.
        assert_eq!(backend.calls(), vec!["is_installed", "create"]);
        let created = backend.created_plan.borrow().clone().unwrap();
        assert_eq!(created.label, "net.dignetwork.dig-node");
        assert_eq!(created.display_name, "DIG NETWORK: NODE");
    }

    #[test]
    fn existing_service_is_stopped_deleted_then_recreated_no_1073() {
        // The service already exists — a naive `create` would hit Windows error 1073. The
        // clean-reinstall must stop + delete FIRST, then recreate, and succeed.
        let backend = MockBackend::new(true);
        let report = reinstall(&backend, &plan()).expect("clean-reinstall must NOT hit 1073");

        assert!(report.existed && report.stopped && report.deleted);
        assert!(report.created);
        // Order: probe, stop, delete, (removal re-probe), create — delete precedes create,
        // which is the whole point (no 1073).
        let calls = backend.calls();
        let create_idx = calls.iter().position(|c| c == "create").unwrap();
        let delete_idx = calls.iter().position(|c| c == "delete").unwrap();
        let stop_idx = calls.iter().position(|c| c == "stop").unwrap();
        assert!(stop_idx < delete_idx, "stop before delete: {calls:?}");
        assert!(delete_idx < create_idx, "delete before create: {calls:?}");
        assert_eq!(calls.last().map(String::as_str), Some("create"));
    }

    #[test]
    fn reinstall_recreates_even_when_stop_fails() {
        // A registered-but-stopped service errors on `stop`; that is best-effort and must NOT
        // block the delete + recreate.
        let backend = MockBackend::with_failing_stop(true);
        let report = reinstall(&backend, &plan()).expect("stop failure is non-fatal");

        assert!(report.existed);
        assert!(!report.stopped, "stop failed, so it is not marked stopped");
        assert!(report.deleted && report.created);
        let calls = backend.calls();
        assert!(calls.contains(&"delete".to_string()));
        assert!(calls.contains(&"create".to_string()));
    }

    // -- idempotent `dign start` (#772): already-running is SUCCESS, not a hard error --------

    #[test]
    fn already_running_is_recognised_across_all_os_signatures() {
        // The exact Windows SCM 1056 message the user hit, plus the launchd/systemd equivalents.
        assert!(is_already_running_error(
            "[SC] StartService FAILED 1056:

An instance of the service is already running."
        ));
        assert!(is_already_running_error("service already loaded"));
        assert!(is_already_running_error("Operation already in progress"));
        assert!(is_already_running_error(
            "Job for x.service is already active"
        ));
        // Case-insensitive.
        assert!(is_already_running_error(
            "AN INSTANCE OF THE SERVICE IS ALREADY RUNNING"
        ));
    }

    #[test]
    fn a_genuine_start_failure_is_not_treated_as_already_running() {
        // "access denied", "not found", etc. must still surface as real errors.
        assert!(!is_already_running_error("Access is denied."));
        assert!(!is_already_running_error(
            "[SC] StartService FAILED 1058: The service cannot be started"
        ));
        assert!(!is_already_running_error(
            "The specified service does not exist"
        ));
        // Regression: a message merely containing "1056" (e.g. in a path/PID) without the
        // "already" or "running" context must NOT be treated as already-running.
        assert!(!is_already_running_error(
            "An error occurred at pid 1056 in the resolver"
        ));
        assert!(!is_already_running_error(""));
    }

    #[test]
    fn start_outcome_maps_an_already_running_error_to_success() {
        // The regression: an already-running service (SCM 1056) previously surfaced as a HARD
        // error; `dign start` must now report success with `already_running: true` (exit 0).
        let err = io::Error::other(
            "[SC] StartService FAILED 1056:

An instance of the service is already running.",
        );
        let outcome = start_outcome(Err(err)).expect("already-running must map to Ok");
        assert_eq!(outcome.result["already_running"], serde_json::json!(true));
        assert_eq!(outcome.result["started"], serde_json::json!(true));
    }

    #[test]
    fn start_outcome_reports_a_fresh_start_as_success() {
        let outcome = start_outcome(Ok(())).expect("a fresh start is Ok");
        assert_eq!(outcome.result["already_running"], serde_json::json!(false));
        assert_eq!(outcome.result["started"], serde_json::json!(true));
    }

    #[test]
    fn start_outcome_propagates_a_real_start_failure() {
        // A non-idempotent failure (e.g. service missing) must NOT be swallowed as success.
        let err = io::Error::new(
            io::ErrorKind::NotFound,
            "The specified service does not exist",
        );
        assert!(start_outcome(Err(err)).is_err());
    }

    #[test]
    fn naive_create_without_delete_would_hit_1073() {
        // Guard the guard: prove the mock actually reproduces 1073 when a live service is
        // recreated WITHOUT the clean-reinstall delete — otherwise the regression test above
        // would pass vacuously.
        let backend = MockBackend::new(true);
        let err = backend.create(&plan()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("1073"));
    }
}
