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
//! ## Install SCOPE (#526)
//!
//! Every service verb is **scope-explicit**: `--scope <auto|system|user>` (default `auto`) selects
//! which OS scope ([`ServiceScope`]) the registration lives in, resolved by the one pure decision
//! function [`resolve_scope`].
//!
//!   * Linux (systemd) / macOS (launchd) — BOTH scopes exist. `auto` picks **system** when running
//!     as root (what an elevated `dig-installer` needs: a `multi-user.target` unit / a
//!     `/Library/LaunchDaemons` daemon that starts at BOOT with no login session — matching what
//!     dig-node's own native packages already register) and **user** otherwise (the historical
//!     no-elevation desktop install: a `systemd --user` unit / a `gui/<uid>` agent).
//!     Root has NO systemd `--user` D-Bus session, which is precisely why the previous
//!     unconditional user-level preference made an elevated headless install impossible.
//!   * Windows (SCM) — **system scope only**: the Service Control Manager has no per-user services,
//!     so every choice resolves to system and `install`/`uninstall` require an **elevated
//!     (Administrator)** console. This is detected up front and reported with a clear message
//!     rather than failing deep inside `sc.exe`.
//!
//! `install` clears any registration at the OTHER scope first ([`install_at_scope`]) so a host
//! upgrading from a user-level install never runs two units racing for the same port, and
//! `uninstall --scope auto` sweeps BOTH scopes so nothing is left starting the node.
//!
//! The OS calls are behind the [`ServiceBackend`] trait so the clean-reinstall ORDER is
//! unit-tested against a recording mock — CI never shells out to `sc`/`launchctl`/`systemctl`
//! for that part; a real 3-OS install/uninstall round-trip is exercised by the
//! `service-smoke` CI job (`.github/workflows/service-smoke.yml`).

use std::cell::Cell;
use std::ffi::OsString;
use std::io;
use std::net::SocketAddr;
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

// ---------------------------------------------------------------------------------------------
// Service SCOPE (#526): which OS scope a registration lives in, and how one is chosen.
// ---------------------------------------------------------------------------------------------

/// The OS scope a service registration lives in.
///
/// The two scopes are genuinely different registrations in different places, with different
/// survival properties:
///
/// * [`ServiceScope::System`] — a machine-wide registration owned by the privileged principal:
///   a systemd **system** unit (`/etc/systemd/system/…`, `WantedBy=multi-user.target`), a launchd
///   **daemon** (`/Library/LaunchDaemons/…`, `system` domain), or a Windows SCM service. It starts
///   at BOOT, with **no logged-in user session** — the only scope that survives a reboot on a
///   headless host. Registering one requires root/Administrator.
/// * [`ServiceScope::User`] — a per-user registration: a systemd **user** unit
///   (`~/.config/systemd/user/…`) or a launchd **agent** (`gui/<uid>` domain). It needs no
///   elevation, runs as the installing user, and starts when that user's session/manager starts —
///   so on a headless host it may not come back after a reboot at all. Windows SCM has no
///   equivalent, so this scope simply does not exist there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceScope {
    /// Machine-wide, privileged, boot-started (see the type doc).
    System,
    /// Per-user, no elevation required, session-started (see the type doc).
    User,
}

impl ServiceScope {
    /// Whether this is the per-user (no-elevation) scope.
    pub fn is_user(self) -> bool {
        self == ServiceScope::User
    }

    /// The lowercase wire/CLI spelling (`"system"` / `"user"`), used in `--json` output and prose.
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceScope::System => "system",
            ServiceScope::User => "user",
        }
    }

    /// The OTHER scope — the one a stale registration from a previous install could be hiding in
    /// (see [`install_at_scope`]).
    pub fn other(self) -> Self {
        match self {
            ServiceScope::System => ServiceScope::User,
            ServiceScope::User => ServiceScope::System,
        }
    }
}

/// What the operator ASKED for on the command line (`--scope <auto|system|user>`).
///
/// Distinct from [`ServiceScope`] — the resolved answer — because `auto` is not a scope: it is a
/// request to let the host decide ([`resolve_scope`]). Kept as the default so a caller that passes
/// no flag (including a dig-installer release predating #526) behaves exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ScopeChoice {
    /// Let the host decide: system scope when running as root/elevated, user scope otherwise.
    #[default]
    Auto,
    /// Force a machine-wide, boot-started registration (requires root/Administrator).
    System,
    /// Force a per-user registration (ignored on Windows, which has no user scope).
    User,
}

/// Resolve the scope to act on. **The one scope decision in the codebase**, and deliberately PURE:
/// every input is a parameter — no `cfg!`, no `geteuid`, no filesystem — so the complete decision
/// table is unit-tested on any host at any privilege level (a `#[cfg(unix)]`-only scope test would
/// be unfalsifiable on a Windows dev box).
///
/// * `os_supports_user == false` (Windows SCM) ⇒ always [`ServiceScope::System`]: there is exactly
///   one scope, so even an explicit `--scope user` cannot be honoured.
/// * An explicit [`ScopeChoice::System`]/[`ScopeChoice::User`] is **authoritative** — never silently
///   overridden by the privilege level. (Whether the caller may actually register there is a
///   separate, loudly-reported question: [`ensure_privilege_for_scope`].)
/// * [`ScopeChoice::Auto`] follows privilege: root gets the reboot-surviving system registration an
///   elevated installer needs; an ordinary desktop user keeps the historical no-elevation user
///   registration.
pub fn resolve_scope(choice: ScopeChoice, os_supports_user: bool, is_root: bool) -> ServiceScope {
    if !os_supports_user {
        return ServiceScope::System;
    }
    match choice {
        ScopeChoice::System => ServiceScope::System,
        ScopeChoice::User => ServiceScope::User,
        ScopeChoice::Auto if is_root => ServiceScope::System,
        ScopeChoice::Auto => ServiceScope::User,
    }
}

/// The scopes `uninstall` must sweep, in the order to sweep them.
///
/// An explicit choice removes exactly what was named. **`auto` sweeps BOTH scopes** (requested one
/// first) on a user-capable OS: an uninstall that silently leaves the other scope's registration
/// behind is the defect class where a "removed" node keeps starting at boot. Sweeping is safe
/// because each scope is PROBED before anything is deleted ([`remove_registration`]), so a scope
/// holding nothing is never written to.
pub fn uninstall_scopes(
    choice: ScopeChoice,
    os_supports_user: bool,
    is_root: bool,
) -> Vec<ServiceScope> {
    let requested = resolve_scope(choice, os_supports_user, is_root);
    if !os_supports_user || choice != ScopeChoice::Auto {
        return vec![requested];
    }
    vec![requested, requested.other()]
}

/// Whether this OS has a per-user service scope at all. Windows SCM has no per-user services;
/// systemd and launchd both do. The one `cfg!`-reading adapter that feeds the pure
/// [`resolve_scope`] decision.
fn host_supports_user_scope() -> bool {
    !cfg!(windows)
}

/// Whether this process is root (uid 0), read straight from the kernel via `geteuid()`.
///
/// **A syscall, never a spawned `id -u` (#526/B1 — a root LPE).** The privilege level now DECIDES
/// the service scope on EVERY service verb, so this runs while root under exactly the
/// `sudo dig-node install --scope system` the docs prescribe. A spawned bare `id` resolves through
/// `$PATH` — group-writable `/usr/local/bin` leads sudo's default Debian `secure_path`, and macOS
/// sets no `secure_path` at all — so a planted `id` would execute AS ROOT before any gate ran.
/// Worse, an `id` printing a non-zero uid would flip the resolved scope to `User`, and a user-scope
/// target is exempt from the §565 privileged-target gate — one writable `PATH` entry would have
/// switched that gate OFF. `geteuid()` cannot be intercepted and cannot fail, which also removes
/// the failure mode this adapter would otherwise need to report.
///
/// Always `false` off unix, where the answer never reaches a decision: Windows has no user scope, so
/// [`resolve_scope`] short-circuits to system and elevation is checked by the SCM gate
/// ([`is_elevated`]).
#[cfg(unix)]
fn host_is_root() -> bool {
    unix_euid() == 0
}
#[cfg(not(unix))]
fn host_is_root() -> bool {
    false
}

/// The effective uid via `geteuid()`. Infallible by POSIX contract, and spawn-free (see
/// [`host_is_root`]).
#[cfg(unix)]
fn unix_euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, touches no memory, and is documented as always
    // succeeding — there is no error case and no pointer involved.
    unsafe { libc::geteuid() }
}

/// Resolve `choice` against THIS host — the single place the pure [`resolve_scope`] decision meets
/// the real OS and privilege level.
fn host_scope(choice: ScopeChoice) -> ServiceScope {
    resolve_scope(choice, host_supports_user_scope(), host_is_root())
}

// ---------------------------------------------------------------------------------------------
// Privileged OS-tool spawning (#526/B8): every tool this module runs may now run AS ROOT, so none
// of them may be located through an attacker-influenced `$PATH`.
// ---------------------------------------------------------------------------------------------

/// The unix directories an OS tool may be executed from.
///
/// Privileged, distribution-owned locations only. **`/usr/local/bin` is deliberately absent**: it is
/// `root:staff 2775` on Debian/Ubuntu (group-writable, and FIRST in sudo's default `secure_path`)
/// and `<user>:admin 0775` under Intel Homebrew — writable by an unprivileged user, which is the
/// whole vector. Mirrors the fixed-directory rule `dig-installer`'s SPEC §7.6 already states.
///
/// Deliberately NOT `#[cfg(unix)]`: a `cfg`-gated list is unfalsifiable on the other platform, so a
/// user-writable directory could be added to it and every test on a Windows dev box would stay
/// green. Both platform lists are therefore plain functions, asserted on EVERY host.
fn unix_os_tool_dirs() -> Vec<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(PathBuf::from)
        .collect()
}

/// The Windows directories an OS tool may be executed from: `%SystemRoot%\System32` and
/// `%SystemRoot%`, both TrustedInstaller/SYSTEM-owned on a stock install. `system_root` is a
/// PARAMETER (see [`unix_os_tool_dirs`] on why neither list is `cfg`-gated); the environment supplies
/// it only as a location HINT, never as a program name.
fn windows_os_tool_dirs(system_root: &std::path::Path) -> Vec<PathBuf> {
    vec![system_root.join("System32"), system_root.to_path_buf()]
}

/// This host's privileged tool directories.
fn os_tool_dirs() -> Vec<PathBuf> {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        windows_os_tool_dirs(&root)
    } else {
        unix_os_tool_dirs()
    }
}

/// The refusal text when an OS tool is not present in any [`os_tool_dirs`] entry. Named per tool so
/// the message says which one, and kept as constants so the same wording is used everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
const MISSING_TOOL_SC: &str =
    "dig-node: sc.exe was not found in a privileged system directory; refusing to run it from an unverified location";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MISSING_TOOL_LAUNCHCTL: &str =
    "dig-node: launchctl was not found in a privileged system directory; refusing to run it from an unverified location";
#[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
const MISSING_TOOL_SYSTEMCTL: &str =
    "dig-node: systemctl was not found in a privileged system directory; refusing to run it from an unverified location";

/// Locate `program` in [`os_tool_dirs`] and build a [`std::process::Command`] for that ABSOLUTE
/// path, or `None` when it is not present in any of them (fail closed — a tool we cannot locate
/// safely is not run at all, rather than run from wherever `$PATH` points).
///
/// Beyond resolving our OWN spawns, this pins the CHILD's environment, which is what closes the
/// dependency's half of the same hole: `service-manager` selects its **WinSW** backend whenever a
/// `winsw.exe` is anywhere on `$PATH` or `%WINSW_PATH%` names an existing file, and then executes
/// that binary as the (elevated) installer — a planted `winsw.exe` would hand an attacker the whole
/// service definition. So `PATH` is replaced with the fixed list and `WINSW_PATH` is removed.
fn os_tool(program: &str) -> Option<std::process::Command> {
    let dirs = os_tool_dirs();
    let path = dirs.iter().map(|d| d.join(program)).find(|p| p.is_file())?;
    let mut cmd = std::process::Command::new(path);
    let joined = std::env::join_paths(dirs.iter()).ok()?;
    cmd.env("PATH", joined);
    cmd.env_remove("WINSW_PATH");
    Some(cmd)
}

/// Pin THIS process's `PATH` to [`os_tool_dirs`] and drop `WINSW_PATH`, for the duration of a
/// privileged service verb.
///
/// [`os_tool`] hardens the spawns this module makes; this hardens the ones it does NOT control —
/// `service-manager` shells out to `systemctl`/`launchctl`/`sc` by BARE NAME, and unix resolves a
/// bare name with `execvp` against the CALLING process's `PATH` (not a child `PATH` we set). Since
/// every one of those spawns can now happen as root, the process-wide value is the only place the
/// lookup can actually be constrained.
fn harden_process_path_for_privileged_spawns() {
    if let Ok(joined) = std::env::join_paths(os_tool_dirs().iter()) {
        std::env::set_var("PATH", joined);
    }
    std::env::remove_var("WINSW_PATH");
}

/// Refuse a system-scope registration that the caller cannot actually make, with a message that
/// says what to do — rather than failing cryptically deep inside `systemctl`/`launchctl`, and
/// rather than silently downgrading to user scope (which on a headless host would not survive a
/// reboot: exactly the defect #526 fixes). PURE, so the policy is table-tested.
///
/// Windows is exempt: it has no user scope, and its elevation requirement is reported by its own
/// SCM gate ([`is_elevated`]) with Windows-specific advice.
fn ensure_privilege_for_scope(
    scope: ServiceScope,
    os_supports_user: bool,
    is_root: bool,
) -> io::Result<()> {
    if !os_supports_user || scope.is_user() || is_root {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "dig-node: registering a system-level (machine-wide, boot-started) service requires \
         root. Re-run with `sudo dig-node install --scope system`, or install at user scope \
         (`--scope user`) — noting that a user-scope service only starts with your login \
         session and so may not come back after a reboot on a headless host.",
    ))
}

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
    let output = os_tool("sc.exe")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, MISSING_TOOL_SC))?
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

/// What a per-scope removal attempt did — the reporting unit for the cross-scope migration
/// ([`install_at_scope`]) and for `uninstall` ([`remove_registrations`]).
///
/// `found` (what the PROBE saw) and `removed` (what the OS deregistration actually did) are
/// deliberately separate, because **the probe is advisory and the deregistration is authoritative**:
/// `launchctl print gui/<uid>/<label>` cannot see a per-user agent from a session with no Aqua/GUI
/// domain (a headless CI runner, an ssh login), so it false-negatives on a service that IS
/// registered. Only `removed` proves anything; `found` explains, and `indeterminate` admits when
/// absence was never established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRemoval {
    /// The scope this attempt addressed.
    pub scope: ServiceScope,
    /// The probe SAW a registration at this scope. Advisory only — a `false` here does NOT prove
    /// absence (see the type doc).
    pub found: bool,
    /// The OS deregistration succeeded. The authoritative signal.
    pub removed: bool,
    /// Absence was never established: the probe failed (or said nothing was there) AND the removal
    /// did not succeed either — so whether a registration remains is UNKNOWN, and must not be
    /// reported as a clean uninstall.
    pub indeterminate: bool,
    /// Why the probe or the removal failed, when one did. `None` on success and on a clean
    /// "nothing registered here".
    pub error: Option<String>,
}

/// How hard to try at a scope — the distinction that keeps a probe false-negative from turning into
/// a silent no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalMode {
    /// The scope the operator NAMED (or `auto` resolved to). Deregistered UNCONDITIONALLY: the OS
    /// removal call is the authority, so a probe that wrongly reports absence can never turn the
    /// uninstall into a no-op. (This is also the pre-#526 behaviour of `uninstall`, which always
    /// called delete outright.)
    Requested,
    /// A scope being swept for a stale registration nobody asked about (the other scope during
    /// `install`, the second scope under `uninstall --scope auto`). PROBE-GATED: nothing is written
    /// unless a registration is actually seen, so a sweep can never disturb an unrelated scope.
    Swept,
}

/// Deregister the service at ONE scope, best-effort, reporting exactly what happened.
///
/// Never returns `Err`: the caller decides which combination of per-scope outcomes is fatal (a stale
/// swept registration is not; a named scope left behind is). See [`RemovalMode`] for why a
/// [`RemovalMode::Requested`] scope is removed without trusting the probe.
pub fn remove_registration<B: ServiceBackend + ?Sized>(
    backend: &B,
    scope: ServiceScope,
    mode: RemovalMode,
) -> ScopeRemoval {
    let mut removal = ScopeRemoval {
        scope,
        found: false,
        removed: false,
        indeterminate: false,
        error: None,
    };
    let probe = backend.is_installed();
    match &probe {
        Ok(found) => removal.found = *found,
        Err(e) => {
            removal.error = Some(format!("could not determine whether it is registered: {e}"))
        }
    }
    // A sweep touches nothing it did not positively see — an unrelated scope must never be written
    // to on the strength of a guess. A probe FAILURE leaves the swept scope indeterminate: absence
    // was not established, and the caller reports that rather than assuming it is clean.
    if mode == RemovalMode::Swept && !removal.found {
        removal.indeterminate = probe.is_err();
        return removal;
    }
    // Best-effort stop first so nothing keeps holding the node's port past the deregistration.
    let _ = backend.stop();
    match backend.delete() {
        Ok(()) => removal.removed = true,
        Err(e) => {
            removal.indeterminate = removal_failure_is_indeterminate(probe.is_err(), e.kind());
            removal.error = Some(e.to_string());
        }
    }
    removal
}

/// PURE: after a removal FAILED, is the scope's state unknown (⇒ must be reported) rather than
/// genuinely empty (⇒ "nothing to uninstall")?
///
/// Classifying by the delete error's KIND is what keeps a real leftover from being reported as
/// absence (#526/B4). `NotFound` is the OS positively saying there is nothing registered — the only
/// honest "empty" signal. Anything else (`PermissionDenied` on a root-owned unit, a busy manager, an
/// unreadable domain, a tool that could not run) leaves a registration that MAY still be there:
/// e.g. an ssh session with no Aqua domain false-negatives the launchd probe AND fails `unload`
/// before the plist is removed — the plist survives and starts at next login, so telling the
/// operator "nothing was installed" would be a lie. An unreadable probe is likewise unknown.
fn removal_failure_is_indeterminate(probe_failed: bool, delete_error: io::ErrorKind) -> bool {
    probe_failed || delete_error != io::ErrorKind::NotFound
}

/// Sweep EVERY account's user-scope registration off the filesystem, stopping each running instance
/// first (#526/B3). Best-effort: the returned report is what the caller surfaces.
///
/// The per-account stop is what keeps the elevated install viable for the upgrade population: a
/// still-running user-level node holds the node's port, so the `dig-node start` that dig-installer
/// treats as a hard error would fail with `EADDRINUSE` on exactly the path this feature enables.
/// Both stops are best-effort and spawn only through [`os_tool`] (absolute path, pinned `PATH`).
fn sweep_other_accounts_user_scope() -> crate::user_scope::UserScopeSweep {
    let unit_file_name = format!(
        "{}.service",
        label()
            .map(|l| l.to_script_name())
            .unwrap_or_else(|_| "dignetwork-dig-node".to_string())
    );
    crate::user_scope::sweep(&unit_file_name, SERVICE_LABEL, |registration| {
        // launchd: root CAN address another user's GUI domain, given the uid — which is read from
        // the plist's own owner, never from a spawned name lookup.
        if let (Some(uid), Some(mut cmd)) = (registration.uid, os_tool("launchctl")) {
            let _ = cmd
                .args(["bootout", &format!("gui/{uid}/{SERVICE_LABEL}")])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        // systemd: `--machine=<account>@.host` is how root reaches another account's user manager.
        // The account name is the home directory's own file name, so no passwd lookup is spawned.
        if let (Some(account), Some(mut cmd)) = (
            registration.home.file_name().and_then(|n| n.to_str()),
            os_tool("systemctl"),
        ) {
            let _ = cmd
                .args([
                    "--user",
                    &format!("--machine={account}@.host"),
                    "stop",
                    &unit_file_name,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    })
}

/// Register at the requested scope, first clearing any registration at the OTHER scope.
///
/// **The other-scope sweep is a placement requirement, not a nicety.** A host upgrading from a
/// prior user-level install to a system-level one would otherwise end up with TWO registrations,
/// both starting a node bound to the same port; which one wins is a race, and the stale one can.
/// So the other scope is deregistered BEFORE the requested one is created — never after, which
/// would delete a registration the new one may share state with, and never left to the caller.
///
/// The sweep is best-effort: an unprivileged install cannot delete a system unit, and that must be
/// REPORTED (in the returned [`ScopeRemoval`]) rather than fail an otherwise-good install. `other`
/// is `None` where the platform has only one scope (Windows).
pub fn install_at_scope<T: ServiceBackend, O: ServiceBackend>(
    target: &T,
    other: Option<(&O, ServiceScope)>,
    plan: &InstallPlan,
) -> io::Result<(ReinstallReport, Option<ScopeRemoval>)> {
    let migration =
        other.map(|(backend, scope)| remove_registration(backend, scope, RemovalMode::Swept));
    let report = reinstall(target, plan)?;
    Ok((report, migration))
}

/// Remove at several scopes, in order, reporting each ([`remove_registration`]).
pub fn remove_registrations(
    targets: &[(&dyn ServiceBackend, ServiceScope, RemovalMode)],
) -> Vec<ScopeRemoval> {
    targets
        .iter()
        .map(|(backend, scope, mode)| remove_registration(*backend, *scope, *mode))
        .collect()
}

/// Turn per-scope removal results into the `uninstall` [`Outcome`], failing LOUDLY on anything
/// less than a complete removal.
///
/// * Any scope found-but-not-removed, or left indeterminate ⇒ `Err`: an uninstall that leaves a
///   registration behind — or cannot tell whether it did — must never report success, which is how
///   a "removed" node keeps starting at boot.
/// * Nothing removed anywhere, and nothing unresolved ⇒ `Err(NotFound)`: there was nothing to
///   uninstall. Any removal error collected along the way is carried as context, since the reason a
///   delete failed is the best evidence available for "there was nothing here".
/// * Otherwise ⇒ success, naming every scope removed.
fn uninstall_outcome(removals: Vec<ScopeRemoval>) -> io::Result<Outcome> {
    let removed: Vec<&'static str> = removals
        .iter()
        .filter(|r| r.removed)
        .map(|r| r.scope.as_str())
        .collect();
    let problems: Vec<String> = removals
        .iter()
        .filter(|r| r.indeterminate || (r.found && !r.removed))
        .map(|r| {
            let why = r.error.as_deref().unwrap_or("removal did not take effect");
            format!("{} scope: {why}", r.scope.as_str())
        })
        .collect();

    if !problems.is_empty() {
        let removed_note = if removed.is_empty() {
            "nothing was removed".to_string()
        } else {
            format!("removed at: {}", removed.join(", "))
        };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "dig-node: could not fully uninstall service \"{SERVICE_LABEL}\" ({removed_note}). \
                 Unresolved: {}. Re-run elevated (e.g. `sudo dig-node uninstall --scope system`) — \
                 a registration left behind will keep starting the node.",
                problems.join("; ")
            ),
        ));
    }
    if removed.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, {
            let scopes = removals
                .iter()
                .map(|r| r.scope.as_str())
                .collect::<Vec<_>>()
                .join(" or ");
            let reasons = removals
                .iter()
                .filter_map(|r| {
                    r.error
                        .as_deref()
                        .map(|e| format!("{} scope: {e}", r.scope.as_str()))
                })
                .collect::<Vec<_>>();
            let mut msg = format!(
                "dig-node: no service registration for \"{SERVICE_LABEL}\" was found at \
                     {scopes} scope — nothing to uninstall."
            );
            if !reasons.is_empty() {
                msg.push_str(&format!(" ({})", reasons.join("; ")));
            }
            msg
        }));
    }
    Ok(Outcome::new(
        format!(
            "dig-node: uninstalled service \"{SERVICE_LABEL}\" at {} scope",
            removed.join(" + ")
        ),
        json!({
            "installed": false,
            "registered": false,
            "label": SERVICE_LABEL,
            "removed_scopes": removed,
        }),
    ))
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

/// Refuse baked service-environment entries carrying a CONTROL CHARACTER before they are written
/// into a privileged unit file (#526/B2 — root unit-file injection).
///
/// `service-manager`'s systemd backend writes each entry as one raw line —
/// `Environment="{key}={value}"` — into `/etc/systemd/system/<unit>.service`, with no escaping or
/// validation. Since this change is what causes that file to be written AS ROOT, a value containing
/// a line terminator does not merely corrupt the entry: it appends further DIRECTIVES to a root
/// unit. It is reachable because `config.upstream`/`cache_dir`/`host` derive from environment
/// variables and from `config.json` under `$HOME` — a file an unprivileged user writes whenever
/// elevation leaves `HOME` user-writable (`sudo -E`, `su` without `-`, `doas`, a root shell inside a
/// user session), which is also exactly the shared-cache co-tenancy this module intends.
///
/// The guard is stated over the CLASS — any of `\n`, `\r`, `\0` in a key or a value — and NOT over
/// any particular directive (`ExecStartPre=`, `User=`, …): a guard justified by one attacker action
/// is bypassed by the next variant. Applied to SYSTEM scope, where the file is root-owned and the
/// daemon privileged; a user-scope unit is written by, and runs as, the user who already controls
/// these values, so there is no boundary to cross. PURE, so every arm is unit-tested.
fn ensure_environment_is_unit_file_safe(
    environment: &[(String, String)],
    scope: ServiceScope,
) -> io::Result<()> {
    if scope.is_user() {
        return Ok(());
    }
    let offending = |s: &str| s.contains('\n') || s.contains('\r') || s.contains('\0');
    for (key, value) in environment {
        if offending(key) || offending(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "dig-node: refusing to register a system-level (privileged) service whose \
                     baked environment variable \"{key}\" contains a control character (a \
                     newline, carriage return or NUL). Each variable is written verbatim as one \
                     line of a root-owned systemd unit file, so such a value could append \
                     arbitrary directives that run as root (#526). Fix the value in the \
                     environment or in config.json and re-run `dig-node install`."
                ),
            ));
        }
    }
    Ok(())
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
///
/// Since #526 this genuinely fires on unix too (a root systemd unit / launchd daemon is as
/// privileged as a Windows SYSTEM service), so its refusal NAMES what failed: the offending
/// directory LEVEL (the gate walks every ancestor, and an operator cannot act on "somewhere in this
/// path is user-writable") or the program FILE itself. The canonical installer target
/// (`/opt/dig/bin/dig-node`, root-owned `0755`) clears both.
fn ensure_service_target_is_safe(
    program: &std::path::Path,
    scope: ServiceScope,
    allow_insecure_override: bool,
) -> io::Result<()> {
    // A user-level service runs as the installing user: swapping a binary that user already owns
    // grants that user nothing it lacked. No privilege boundary, no LPE — always allowed.
    if scope.is_user() {
        return Ok(());
    }
    let dir = program.parent().unwrap_or(program);
    let refusal = classify_system_target(
        crate::security::first_unprivileged_ancestor(dir),
        crate::security::file_is_privileged(program),
    );
    let Some(refusal) = refusal else {
        return Ok(());
    };
    // Explicit, default-off test/dev opt-out — a controlled install of an unreleased build from a
    // build directory (see the env-var doc). Never set on an end-user machine, and INERT for a
    // genuinely-root system registration (the caller applies that rule — #526/B7).
    if allow_insecure_override {
        eprintln!(
            "dig-node: WARN {ALLOW_INSECURE_SERVICE_TARGET_ENV} is set — registering a \
             system-level service pointing at \"{}\", which is not privileged-owned ({}). This is \
             a privilege-escalation risk (#565) and is intended ONLY for test/dev installs of an \
             unreleased build.",
            program.display(),
            refusal.describe(),
        );
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "dig-node: refusing to register a system-level (privileged) service pointing at \
             \"{}\": {}. Registering it would let a non-privileged local user replace that binary \
             and gain persistent SYSTEM/root code execution (a privilege-escalation vector, #565). \
             Install dig-node into a protected, admin-owned location — via the DIG installer or a \
             native OS package — and re-run `dig-node install` from there.",
            program.display(),
            refusal.describe(),
        ),
    ))
}

/// Why a system-scope service target was refused — which of the two independent checks failed, so
/// the message can name it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetRefusal {
    /// A DIRECTORY level in the program's chain is not privileged-owned (it names that level).
    Directory(PathBuf),
    /// The program FILE itself is not privileged-owned (wrong owner, a group/other write bit, or a
    /// symlink) — even though its directory chain is fine.
    ProgramFile,
}

impl TargetRefusal {
    /// The operator-facing clause naming the offending thing.
    fn describe(&self) -> String {
        match self {
            TargetRefusal::Directory(level) => format!(
                "the path level \"{}\" is writable by a non-privileged user",
                level.display()
            ),
            TargetRefusal::ProgramFile => {
                "the program file itself is not owned by root/SYSTEM, or \
                 grants write access beyond its owner (a non-privileged user could rewrite it in \
                 place, which the directory's permissions do not prevent)"
                    .to_string()
            }
        }
    }
}

/// PURE: given the first unprivileged DIRECTORY level (if any) and whether the program FILE itself
/// is privileged, decide whether a system-scope registration is refused, and why.
///
/// Both checks are required and they are independent (#526/B6): a root-owned directory stops the
/// entry being unlinked or renamed, while the file's OWN owner/mode is what stops it being rewritten
/// in place. The directory is reported first because it is the wider problem when both fail.
fn classify_system_target(
    unprivileged_dir_level: Option<&std::path::Path>,
    program_file_privileged: bool,
) -> Option<TargetRefusal> {
    match (unprivileged_dir_level, program_file_privileged) {
        (Some(level), _) => Some(TargetRefusal::Directory(level.to_path_buf())),
        (None, false) => Some(TargetRefusal::ProgramFile),
        (None, true) => None,
    }
}

/// PURE: is the [`ALLOW_INSECURE_SERVICE_TARGET_ENV`] opt-out actually in force?
///
/// It is INERT for a genuinely-root system-scope registration (#526/B7). That combination is a root
/// BOOT DAEMON on a real machine — the one case where the §565 gate matters most — and the env var
/// is inheritable: `sudo -E`, a stray export in a root profile, or a CI value leaking into an
/// operator shell must not be able to switch the gate off for it. The override survives only where
/// it is genuinely needed: an unelevated/dev context, or Windows-without-root semantics.
fn insecure_override_is_effective(env_set: bool, scope: ServiceScope, is_root: bool) -> bool {
    env_set && !(scope == ServiceScope::System && is_root)
}

/// On Windows, is this process running elevated (Administrator)? Used to fail
/// `install`/`uninstall` early with a helpful message instead of a cryptic SCM
/// access-denied. Always `true` off Windows (those paths are user-level).
#[cfg(windows)]
fn is_elevated() -> bool {
    // Probe by attempting to open the SCM with all-access; only an elevated token
    // can. Shelling to `net session` is the classic check; doing it via `sc` query
    // would not distinguish. Use a lightweight `net session` invocation.
    os_tool("net.exe")
        .and_then(|mut cmd| {
            cmd.arg("session")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .ok()
        })
        .map(|s| s.success())
        // A `net.exe` we cannot locate in a privileged directory means we cannot establish
        // elevation — fail CLOSED (report not-elevated) rather than proceed unverified.
        .unwrap_or(false)
}
#[cfg(not(windows))]
fn is_elevated() -> bool {
    true
}

/// The real [`ServiceBackend`]: the native OS service manager pinned to ONE
/// [`ServiceScope`], plus the scope-aware OS existence probe and the Windows display-name
/// override + read-back verify.
pub struct SystemServiceBackend {
    label: ServiceLabel,
    manager: Box<dyn ServiceManager>,
    /// The scope this backend acts on — every probe/create/delete addresses THAT scope only.
    scope: ServiceScope,
    /// Windows-only: whether the post-create `sc qc` read-back confirmed the display name was
    /// actually applied. `None` off Windows (nothing to verify) or before a `create` has run.
    display_name_verified: Cell<Option<bool>>,
}

impl SystemServiceBackend {
    /// Acquire the native service manager pinned to `scope`.
    ///
    /// A scope the platform's manager cannot address is an ERROR naming the scope — never a silent
    /// downgrade to the other one, which is how a requested boot-surviving registration would
    /// quietly become a session-only one (#526).
    pub fn new(scope: ServiceScope) -> io::Result<Self> {
        let mut manager = <dyn ServiceManager>::native()?;
        let level = if scope.is_user() {
            ServiceLevel::User
        } else {
            ServiceLevel::System
        };
        manager.set_level(level).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "dig-node: this platform's service manager cannot register a {}-level \
                     service ({e})",
                    scope.as_str()
                ),
            )
        })?;
        Ok(Self {
            label: label()?,
            manager,
            scope,
            display_name_verified: Cell::new(None),
        })
    }

    /// The scope this backend acts on.
    pub fn scope(&self) -> ServiceScope {
        self.scope
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
        // Propagated, NOT swallowed into `false`: a probe that could not run at all is a THIRD
        // state (unknown), and collapsing it to "not installed" is what makes a failed removal look
        // like "nothing was installed" (#526/B4).
        query_installed(&os_native_service_name(&self.label), self.scope)
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

/// Probe whether a service named `service_name` is registered AT `scope`, per OS. Best-effort: a
/// probe that cannot run (tool missing) reports `false` so the clean-reinstall proceeds to create.
/// Windows SCM has exactly one scope, so `scope` carries no information there.
#[cfg(windows)]
fn query_installed(service_name: &str, _scope: ServiceScope) -> io::Result<bool> {
    // `sc query <name>` exits 0 when the service exists, 1060 (does-not-exist) otherwise.
    let status = os_tool("sc.exe")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, MISSING_TOOL_SC))?
        .args(["query", service_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(status.success())
}

/// macOS launchd existence probe: `launchctl print <domain>/<label>` exits 0 when the service
/// is bootstrapped in that scope's domain.
#[cfg(target_os = "macos")]
fn query_installed(service_name: &str, scope: ServiceScope) -> io::Result<bool> {
    let domain = launchd_domain_target(service_name, scope);
    let status = os_tool("launchctl")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, MISSING_TOOL_LAUNCHCTL))?
        .args(["print", &domain])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(status.success())
}

/// Linux systemd existence probe: `systemctl [--user] cat <label>.service` exits 0 when the
/// unit file exists in that scope (non-zero "No files found" otherwise). `--user` addresses the
/// per-user manager, its absence the system manager — the two hold DIFFERENT unit files, so the
/// flag must track the scope being probed or the probe reports on the wrong registration.
#[cfg(all(unix, not(target_os = "macos")))]
fn query_installed(service_name: &str, scope: ServiceScope) -> io::Result<bool> {
    let unit = format!("{service_name}.service");
    let mut cmd = os_tool("systemctl")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, MISSING_TOOL_SYSTEMCTL))?;
    if scope.is_user() {
        cmd.arg("--user");
    }
    let status = cmd
        .args(["cat", &unit])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(status.success())
}

/// The launchd domain target `launchctl print` addresses for `scope`: `gui/<uid>/<label>` for a
/// per-user AGENT, `system/<label>` for a machine-wide DAEMON — the same `system` domain
/// `packaging/macos/scripts/postinstall` bootstraps into.
#[cfg(target_os = "macos")]
fn launchd_domain_target(service_name: &str, scope: ServiceScope) -> String {
    if scope.is_user() {
        format!("gui/{}/{}", unix_euid(), service_name)
    } else {
        format!("system/{service_name}")
    }
}

/// Override the Windows service display name (`sc config <name> displayname= "<display>"`).
/// Best-effort; a failure is swallowed (the service is already usable under its id) — the
/// caller reads back the result via [`query_windows_display_name`].
#[cfg(windows)]
fn set_windows_display_name(service_name: &str, display_name: &str) {
    let args = display_name_config_args(service_name, display_name);
    if let Some(mut cmd) = os_tool("sc.exe") {
        let _ = cmd
            .args(&args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Read back the Windows service's CURRENT display name via `sc qc <name>`, so
/// [`SystemServiceBackend::create`] can confirm the `sc config displayname=` override actually
/// took effect rather than trusting its exit code alone.
#[cfg(windows)]
fn query_windows_display_name(service_name: &str) -> io::Result<Option<String>> {
    let output = os_tool("sc.exe")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, MISSING_TOOL_SC))?
        .args(["qc", service_name])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_sc_qc_display_name(&stdout).map(str::to_string))
}

/// Apply the SAME non-loopback-bind refusal at INSTALL time that the bind site enforces
/// ([`crate::config::host_override_refusal`], #1662): baking a non-loopback `DIG_NODE_HOST`
/// into the service env WITHOUT `DIG_NODE_ALLOW_REMOTE=1` would otherwise install a service
/// that fails closed on its first start — a confusing operator experience. Refusing here
/// surfaces the identical guard message up front, before anything is registered. PURE, so the
/// policy is unit-tested without touching the OS; reuses the one canonical predicate rather
/// than re-deriving the loopback rule.
fn ensure_install_host_allowed(config: &Config) -> io::Result<()> {
    match crate::config::host_override_refusal(config.host, config.allow_remote) {
        Some(msg) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("dig-node: {msg}"),
        )),
        None => Ok(()),
    }
}

/// Install dig-node as an auto-starting OS service that runs `dig-node run` on the configured
/// loopback port, via the clean-reinstall contract (stop → delete → recreate on an existing
/// service; create otherwise — see the module doc for why this never auto-starts). On Windows,
/// also configures SCM recovery actions (restart-on-crash) — see
/// [`configure_windows_recovery`] — so a crashed service comes back up the same way systemd
/// (`Restart=on-failure`) and launchd (`KeepAlive`) already do for Linux/macOS via
/// `service-manager`'s own defaults.
///
/// `scope` selects WHERE the registration lands (#526): [`ScopeChoice::Auto`] — the default, and
/// what a caller passing no flag gets — keeps the historical no-elevation user registration for a
/// desktop user while giving an ELEVATED installer the machine-wide, boot-started one it needs on a
/// headless host. Any registration at the other scope is cleared first ([`install_at_scope`]).
pub fn install(config: &Config, scope: ScopeChoice) -> io::Result<Outcome> {
    harden_process_path_for_privileged_spawns();
    // #1667: fail fast on a remote bind that lacks the escape hatch, BEFORE any side effect
    // (service registration, state-dir harden), so the refusal leaves nothing behind.
    ensure_install_host_allowed(config)?;

    let scope = host_scope(scope);
    ensure_privilege_for_scope(scope, host_supports_user_scope(), host_is_root())?;

    if cfg!(windows) && !is_elevated() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dig-node: installing a Windows service requires an elevated \
             (Administrator) console. Re-run this in a terminal opened with \
             \"Run as administrator\".",
        ));
    }

    let backend = SystemServiceBackend::new(scope)?;
    let program = current_exe()?;
    // §565 LPE gate: before touching anything, refuse a privileged (system-level) registration
    // whose program binary sits in a user-writable directory — a swapped binary would run as
    // SYSTEM/root on the next start. Checked FIRST so a refusal has no side effects (no state-dir
    // harden, no service create). A user-level install runs as the invoking user and is allowed.
    ensure_service_target_is_safe(
        &program,
        scope,
        insecure_override_is_effective(insecure_service_target_allowed(), scope, host_is_root()),
    )?;
    let plan = build_plan(config, program.clone());
    // #526/B2: refuse a control character in the baked environment BEFORE anything is written —
    // each entry becomes one raw line of a root-owned systemd unit file.
    ensure_environment_is_unit_file_safe(&plan.environment, scope)?;

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

    // Clear a registration at the OTHER scope before creating this one, so a host upgrading from a
    // previous user-level install never ends up with two units racing for the node's port. Skipped
    // where the platform has only one scope (Windows SCM).
    let other_scope = scope.other();
    let other_backend = host_supports_user_scope()
        .then(|| SystemServiceBackend::new(other_scope).ok())
        .flatten();
    // The OS-manager sweep above can only see the CURRENT account's user scope, and as root it can
    // see none at all (#526/B3: root has no systemd `--user` session, and `gui/<uid>` is uid 0's
    // domain). Registering a system service while another account's user-level node keeps running
    // would leave two enabled units on the same port — and the still-running one holds it, so the
    // `dig-node start` that dig-installer treats as fatal would fail. So when registering at SYSTEM
    // scope, additionally sweep every account's registration on the FILESYSTEM.
    let account_sweep = (scope == ServiceScope::System && host_supports_user_scope())
        .then(|| sweep_other_accounts_user_scope());
    let (report, migration) = install_at_scope(
        &backend,
        other_backend.as_ref().map(|b| (b, other_scope)),
        &plan,
    )?;

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

    let action = if report.existed {
        "reinstalled (stopped + deleted the existing service, then recreated it)"
    } else {
        "installed"
    };
    let addr = config.bind_addr();
    let mut summary = format!(
        "dig-node: {action} as a {}-level service\n  \
         id:      {SERVICE_LABEL}\n  \
         display: {SERVICE_DISPLAY_NAME}\n  \
         program: {}\n  serves:  http://{addr}\n  Set the DIG Chrome extension's \"server host\" to {addr}.\n  \
         Start it now with: dig-node start",
        scope.as_str(),
        program.display(),
    );
    // Report the cross-scope migration: a cleared stale registration is news, and so is one that
    // could NOT be cleared (it would keep starting a second node bound to the same port).
    if let Some(m) = &migration {
        if m.removed {
            summary.push_str(&format!(
                "\n  note: removed a previous {}-scope registration of this service.",
                m.scope.as_str()
            ));
        } else if m.found || m.indeterminate {
            let err = m.error.as_deref().unwrap_or("removal did not take effect");
            summary.push_str(&format!(
                "\n  WARN a {}-scope registration of this service is still present and could \
                 not be removed ({err}); both may try to serve the same port. Remove it with: \
                 dig-node uninstall --scope {}",
                m.scope.as_str(),
                m.scope.as_str()
            ));
        }
    }
    // Report the per-account filesystem sweep truthfully: what was cleared, what was left behind,
    // and — whenever a system registration was made — the residual this mechanism cannot reach.
    if let Some(sweep) = &account_sweep {
        for home in &sweep.removed {
            summary.push_str(&format!(
                "
  note: removed (and stopped) the user-level registration belonging to {}.",
                home.display()
            ));
        }
        for (home, why) in &sweep.failed {
            summary.push_str(&format!(
                "
  WARN could not remove the user-level registration belonging to {} ({why}); it                  may keep starting a second node on the same port. Have that user run: dig-node                  uninstall --scope user",
                home.display()
            ));
        }
        summary.push_str(&format!(
            "
  note: {}",
            crate::user_scope::UserScopeSweep::residual_note()
        ));
    }
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
        "scope": scope.as_str(),
        "program": program.display().to_string(),
        "addr": addr,
        "upstream": config.upstream,
        "recovery_configured": recovery_configured,
    });
    if let Some(verified) = display_name_verified {
        result["display_name_verified"] = json!(verified);
    }
    if let Some(sweep) = &account_sweep {
        result["user_scope_sweep"] = json!({
            "removed_accounts": sweep
                .removed
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
            "failed_accounts": sweep
                .failed
                .iter()
                .map(|(p, why)| json!({ "account": p.display().to_string(), "error": why }))
                .collect::<Vec<_>>(),
            "residual": crate::user_scope::UserScopeSweep::residual_note(),
        });
    }
    if let Some(m) = &migration {
        result["migrated_from_scope"] = json!({
            "scope": m.scope.as_str(),
            "found": m.found,
            "removed": m.removed,
            "indeterminate": m.indeterminate,
            "error": m.error,
        });
    }
    Ok(Outcome::new(summary, result))
}

/// Uninstall the dig-node service, stopping it first (best-effort) so the removal is clean.
///
/// `scope` selects WHAT to remove (#526): an explicit scope removes exactly that one, while
/// [`ScopeChoice::Auto`] — the default — sweeps BOTH scopes, so an uninstall can never silently
/// leave the other scope's registration behind still starting the node
/// ([`uninstall_scopes`]/[`uninstall_outcome`]). Every scope is reported, and anything short of a
/// complete removal is an error, never a silent success.
pub fn uninstall(scope: ScopeChoice) -> io::Result<Outcome> {
    harden_process_path_for_privileged_spawns();
    if cfg!(windows) && !is_elevated() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dig-node: uninstalling a Windows service requires an elevated \
             (Administrator) console.",
        ));
    }
    let scopes = uninstall_scopes(scope, host_supports_user_scope(), host_is_root());
    // Build a backend per scope first: a scope whose manager cannot be acquired is reported as an
    // unresolved scope rather than aborting the sweep of the others.
    let backends: Vec<(ServiceScope, io::Result<SystemServiceBackend>)> = scopes
        .into_iter()
        .map(|s| (s, SystemServiceBackend::new(s)))
        .collect();
    // The FIRST scope is the one the operator named (or `auto` resolved to) and is removed
    // unconditionally; any further scope is only being swept for a stale registration.
    let removals = backends
        .iter()
        .enumerate()
        .map(|(i, (scope, backend))| {
            let mode = if i == 0 {
                RemovalMode::Requested
            } else {
                RemovalMode::Swept
            };
            match backend {
                Ok(b) => remove_registration(b, *scope, mode),
                Err(e) => ScopeRemoval {
                    scope: *scope,
                    found: false,
                    removed: false,
                    // A scope whose manager cannot even be acquired is UNKNOWN, not clean.
                    indeterminate: true,
                    error: Some(e.to_string()),
                },
            }
        })
        .collect();
    uninstall_outcome(removals)
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

/// Start the installed service at `scope` (#526 — the same resolution `install` used, so the
/// default `auto` starts what a default `install` registered). Idempotent: an already-running
/// service is reported as success (#772), never a hard error.
pub fn start(scope: ScopeChoice) -> io::Result<Outcome> {
    harden_process_path_for_privileged_spawns();
    let backend = SystemServiceBackend::new(host_scope(scope))?;
    start_outcome(backend.start())
}

/// Stop the running service at `scope` (#526).
pub fn stop(scope: ScopeChoice) -> io::Result<Outcome> {
    harden_process_path_for_privileged_spawns();
    let backend = SystemServiceBackend::new(host_scope(scope))?;
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
    let (serving, summary) = match probe_health(addr) {
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
        json!({ "serving": serving, "addr": addr.to_string(), "health_url": url }),
    ))
}

/// Minimal blocking HTTP/1.0 `GET /health` probe over loopback. Returns whether
/// the response status line is `2xx`. Avoids pulling an async HTTP client into the
/// status path. Takes a typed [`SocketAddr`] so an IPv6 target is connected to — and
/// rendered into the probe URL — without the authority ever being spelled by hand (#1682).
fn probe_health(addr: SocketAddr) -> io::Result<bool> {
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
    use std::rc::Rc;

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

    // #1667: the install path must apply the SAME non-loopback-bind refusal that the
    // bind site does, so `dig-node install DIG_NODE_HOST=0.0.0.0` (no escape hatch) is
    // refused AT INSTALL rather than installing a service that fails closed on first start.
    #[test]
    fn ensure_install_host_allowed_refuses_remote_host_without_escape_hatch_1667() {
        let config = Config {
            host: Some(std::net::Ipv4Addr::new(0, 0, 0, 0).into()),
            allow_remote: false,
            ..Config::default()
        };
        let err = ensure_install_host_allowed(&config).expect_err(
            "a non-loopback host without DIG_NODE_ALLOW_REMOTE=1 must be refused at install",
        );
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("non-loopback"));
    }

    #[test]
    fn ensure_install_host_allowed_permits_remote_host_with_escape_hatch_1667() {
        let config = Config {
            host: Some(std::net::Ipv4Addr::new(0, 0, 0, 0).into()),
            allow_remote: true,
            ..Config::default()
        };
        assert!(ensure_install_host_allowed(&config).is_ok());
    }

    #[test]
    fn ensure_install_host_allowed_permits_loopback_and_default_1667() {
        let loopback = Config {
            host: Some(std::net::Ipv4Addr::LOCALHOST.into()),
            ..Config::default()
        };
        assert!(ensure_install_host_allowed(&loopback).is_ok());
        assert!(ensure_install_host_allowed(&Config::default()).is_ok());
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
            ensure_service_target_is_safe(&program, ServiceScope::User, false).is_ok(),
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
        let err = ensure_service_target_is_safe(&program, ServiceScope::System, false)
            .expect_err("a system-level install from a user-writable dir must be refused");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // The message must name the LPE class + the offending path so an operator can act. (Which
        // of the two independent checks fires depends on the host and on whether the suite runs as
        // root — see the directory-level test — so only the class + path are asserted here.)
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
            ensure_service_target_is_safe(&program, ServiceScope::System, true).is_ok(),
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
        assert!(!probe_health(SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 1)).unwrap());
    }

    #[test]
    fn system_backend_builds_and_probes_an_unregistered_service_cleanly() {
        // Building the native backend + probing for a service that is not registered must never
        // panic and must report a boolean (false in a clean env). No service is created.
        if let Ok(backend) = SystemServiceBackend::new(ServiceScope::System) {
            let _installed = backend.is_installed().expect("probe never hard-errors");
            assert_eq!(
                backend.scope(),
                ServiceScope::System,
                "the backend keeps its scope"
            );
            assert_eq!(backend.display_name_verified(), None, "no create() ran yet");
        }
    }

    // -- clean-reinstall orchestration (the core #494 contract), via a recording mock -------

    /// A recording [`ServiceBackend`] mock. `installed` starts at the given value; `delete`
    /// flips it to `false` (a synchronous removal, like systemd/launchd). `create` SIMULATES
    /// the Windows `CreateService 1073` bug: it FAILS if the service still appears installed —
    /// so a test that recreates onto a live service fails exactly as Windows would, and the
    /// clean-reinstall (which deletes first) is proven to defeat it.
    ///
    /// Every call is appended to a log that may be SHARED with a second mock (see
    /// [`MockBackend::tagged`]), each mock tagging its own entries — that shared, tagged log is what
    /// makes the RELATIVE order of two different-scope backends assertable (the #526 cross-scope
    /// migration must deregister the other scope BEFORE creating at the requested one).
    struct MockBackend {
        installed: RefCell<bool>,
        /// Prefix stamped onto this mock's log entries (`""` when it owns the log alone).
        tag: &'static str,
        log: Rc<RefCell<Vec<String>>>,
        created_plan: RefCell<Option<InstallPlan>>,
        fail_stop: bool,
        fail_delete: bool,
        fail_delete_not_found: bool,
        fail_probe: bool,
    }

    impl MockBackend {
        fn new(installed: bool) -> Self {
            Self {
                installed: RefCell::new(installed),
                tag: "",
                log: Rc::new(RefCell::new(Vec::new())),
                created_plan: RefCell::new(None),
                fail_stop: false,
                fail_delete: false,
                fail_delete_not_found: false,
                fail_probe: false,
            }
        }
        fn with_failing_stop(installed: bool) -> Self {
            Self {
                fail_stop: true,
                ..Self::new(installed)
            }
        }
        /// A mock that writes into a SHARED log under `tag`, so two mocks' calls interleave in one
        /// ordered transcript.
        fn tagged(tag: &'static str, log: &Rc<RefCell<Vec<String>>>, installed: bool) -> Self {
            Self {
                tag,
                log: Rc::clone(log),
                ..Self::new(installed)
            }
        }
        /// A mock whose `delete` fails — a registration that is FOUND but cannot be removed (the
        /// case that must never be reported as a silent success).
        fn failing_delete(mut self) -> Self {
            self.fail_delete = true;
            self
        }
        /// A mock whose `delete` fails with `NotFound` — the OS positively reporting that nothing is
        /// registered, which is the ONLY honest "there was nothing here" signal (#526/B4).
        fn failing_delete_not_found(mut self) -> Self {
            self.fail_delete = true;
            self.fail_delete_not_found = true;
            self
        }
        /// A mock whose existence probe errors — an indeterminate scope, which must be REPORTED,
        /// never silently treated as "nothing there".
        fn failing_probe(mut self) -> Self {
            self.fail_probe = true;
            self
        }
        fn record(&self, what: &str) {
            self.log.borrow_mut().push(format!("{}{what}", self.tag));
        }
        fn calls(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
    }

    impl ServiceBackend for MockBackend {
        fn is_installed(&self) -> io::Result<bool> {
            self.record("is_installed");
            if self.fail_probe {
                return Err(io::Error::other("probe failed"));
            }
            Ok(*self.installed.borrow())
        }
        fn stop(&self) -> io::Result<()> {
            self.record("stop");
            if self.fail_stop {
                Err(io::Error::other("not running"))
            } else {
                Ok(())
            }
        }
        fn delete(&self) -> io::Result<()> {
            self.record("delete");
            if self.fail_delete {
                return Err(if self.fail_delete_not_found {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "Unit dignetwork-dig-node.service does not exist",
                    )
                } else {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Failed to connect to bus: Operation not permitted",
                    )
                });
            }
            *self.installed.borrow_mut() = false; // synchronous removal
            Ok(())
        }
        fn create(&self, plan: &InstallPlan) -> io::Result<()> {
            self.record("create");
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

    // -- #526/B1 + B8: nothing privileged is located through $PATH ---------------------------

    /// The B1/B8 root-LPE guard, asserted at the SOURCE level because that is where the property
    /// lives: every OS tool this module runs may now run as root (the privilege level decides the
    /// scope on every verb), so NO spawn may name a program that `$PATH` resolves. A behavioural
    /// test cannot express "and no future spawn either"; this can, and it fails the moment someone
    /// reintroduces `Command::new("systemctl")`.
    #[test]
    fn no_privileged_spawn_names_a_program_that_path_would_resolve_b1_b8() {
        // Only the PRODUCTION half is scanned: this test's own prose necessarily spells the
        // forbidden pattern, and matching itself would make it unfalsifiable.
        let whole = include_str!("service.rs");
        let src = whole
            .split_once(
                "
#[cfg(test)]
mod tests {",
            )
            .map(|(production, _)| production)
            .expect("the test module marks the end of production code");
        let offenders: Vec<(usize, &str)> = src
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains("Command::new("))
            // The ONE legitimate site: inside `os_tool`, which passes an absolute PathBuf it
            // resolved from the fixed privileged directory list.
            .filter(|(_, line)| !line.contains("Command::new(path)"))
            .map(|(i, line)| (i + 1, line.trim()))
            .collect();
        assert!(
            offenders.is_empty(),
            "every OS-tool spawn must go through os_tool() (absolute path from a fixed privileged \
             directory list). A bare program name is resolved through $PATH, and these run as root \
             — a planted binary in a user-writable PATH entry (/usr/local/bin is group-writable on \
             Debian and user-owned under Intel Homebrew, and sudo keeps the user's PATH on macOS) \
             would execute as root. Offending lines: {offenders:?}"
        );
        // The privilege probe itself must be a syscall: an `id -u` spawn was the original defect,
        // and a fake `id` printing a non-zero uid would ALSO flip the resolved scope to `user`,
        // switching the §565 privileged-target gate off.
        assert!(
            !src.contains("\"id\""),
            "the effective uid must come from geteuid(), never a spawned `id`"
        );
    }

    #[test]
    fn neither_platform_tool_directory_list_admits_a_user_writable_location() {
        // BOTH platform lists are asserted on EVERY host: a `cfg`-gated list would let a
        // user-writable directory be added to the unix set while a Windows dev box stayed green.
        let unix = unix_os_tool_dirs();
        let windows = windows_os_tool_dirs(std::path::Path::new(r"C:\Windows"));
        assert!(!unix.is_empty() && !windows.is_empty());
        for bad in [
            // Group-writable on Debian/Ubuntu (root:staff 2775), user-owned under Intel Homebrew —
            // and FIRST in sudo's default secure_path.
            "/usr/local/bin",
            "/usr/local/sbin",
            "/opt/homebrew/bin",
            "/tmp",
            // A relative entry resolves against a CWD the caller chooses.
            ".",
            "",
        ] {
            for (label, dirs) in [("unix", &unix), ("windows", &windows)] {
                assert!(
                    !dirs.iter().any(|d| d == std::path::Path::new(bad)),
                    "{bad:?} is writable by a non-privileged user on a common install and MUST NOT                      be a privileged tool directory ({label}): {dirs:?}"
                );
            }
        }
        // The Windows list stays ANCHORED to the given system root; the unix list is absolute.
        assert!(windows.iter().all(|d| d.starts_with(r"C:\Windows")));
        // A POSIX-absolute leading "/" — asserted as a STRING because `Path::is_absolute` answers
        // for the HOST's rules, and on Windows "/usr/bin" is not absolute (no drive letter), which
        // would make this assertion host-dependent.
        assert!(unix
            .iter()
            .all(|d| d.to_string_lossy().starts_with('/')));
    }

    #[test]
    fn os_tool_fails_closed_for_a_tool_that_is_not_in_a_privileged_directory() {
        // A tool we cannot locate safely is NOT run from wherever $PATH points.
        assert!(os_tool("definitely-not-a-real-os-tool-xyz").is_none());
    }

    // -- #526 scope resolution: the decision, host-independently ------------------------------

    /// The PRIMARY evidence for #526. Every input of [`resolve_scope`] is a parameter, so the
    /// COMPLETE decision table — all 3 choices × 2 OS capabilities × 2 privilege levels — is
    /// asserted on any host, unprivileged. Deliberately NOT `#[cfg(unix)]`-gated: a cfg-gated
    /// scope test is unfalsifiable on a Windows dev box, where an inverted decision would stay
    /// green.
    #[test]
    fn resolve_scope_decision_table_is_exhaustive_across_choice_os_and_privilege() {
        use ScopeChoice::{Auto, System as ChooseSystem, User as ChooseUser};
        use ServiceScope::{System, User};

        // (choice, os_supports_user, is_root) => expected scope
        let table = [
            // Auto: the privilege level decides — root gets a reboot-surviving system unit, a
            // desktop user keeps today's no-elevation user unit.
            (Auto, true, true, System),
            (Auto, true, false, User),
            // An explicit choice is AUTHORITATIVE: never silently overridden by privilege.
            (ChooseSystem, true, true, System),
            (ChooseSystem, true, false, System),
            (ChooseUser, true, true, User),
            (ChooseUser, true, false, User),
            // An OS with no user domain (Windows SCM) has exactly ONE scope, so every input
            // collapses to System — including an explicit `--scope user`, which cannot be honoured.
            (Auto, false, true, System),
            (Auto, false, false, System),
            (ChooseSystem, false, true, System),
            (ChooseSystem, false, false, System),
            (ChooseUser, false, true, System),
            (ChooseUser, false, false, System),
        ];
        assert_eq!(table.len(), 12, "the table must cover 3 × 2 × 2 inputs");

        for (choice, os_supports_user, is_root, expected) in table {
            assert_eq!(
                resolve_scope(choice, os_supports_user, is_root),
                expected,
                "resolve_scope({choice:?}, os_supports_user={os_supports_user}, \
                 is_root={is_root}) must be {expected:?}"
            );
        }
    }

    #[test]
    fn scope_choice_default_is_auto_so_an_older_installer_passing_no_flag_is_unchanged() {
        // BC: dig-installer releases predating `--scope` pass no flag at all. The default MUST be
        // `auto`, and `auto` unprivileged on a user-capable OS MUST stay the pre-#526 user scope.
        assert_eq!(ScopeChoice::default(), ScopeChoice::Auto);
        assert_eq!(
            resolve_scope(ScopeChoice::default(), true, false),
            ServiceScope::User
        );
    }

    #[test]
    fn service_scope_renders_and_inverts() {
        assert_eq!(ServiceScope::User.as_str(), "user");
        assert_eq!(ServiceScope::System.as_str(), "system");
        assert!(ServiceScope::User.is_user());
        assert!(!ServiceScope::System.is_user());
        assert_eq!(ServiceScope::User.other(), ServiceScope::System);
        assert_eq!(ServiceScope::System.other(), ServiceScope::User);
    }

    #[test]
    fn a_system_scope_registration_requires_root_on_a_user_capable_os() {
        // systemd/launchd system units live in root-owned dirs; asking for one unprivileged must
        // fail with an ACTIONABLE message up front, never a cryptic failure deep inside
        // systemctl — and never a silent downgrade to user scope (which would not survive a
        // reboot without a login session, the whole #526 defect).
        let err = ensure_privilege_for_scope(ServiceScope::System, true, false)
            .expect_err("system scope unprivileged must be refused");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let msg = err.to_string();
        assert!(msg.contains("system"), "names the scope: {msg}");
        assert!(msg.contains("root"), "names the missing privilege: {msg}");

        // The cases that must NOT be refused: root asking for system, anyone asking for user,
        // and Windows (no user domain — elevation is checked by its own SCM gate).
        assert!(ensure_privilege_for_scope(ServiceScope::System, true, true).is_ok());
        assert!(ensure_privilege_for_scope(ServiceScope::User, true, false).is_ok());
        assert!(ensure_privilege_for_scope(ServiceScope::System, false, false).is_ok());
    }

    // -- #526 cross-scope migration: a PLACEMENT fix, proven by ORDER ------------------------

    /// The positional-shadowing defect: a host upgrading from a prior USER-level install to a
    /// system-level one would end up with TWO registrations, both binding the node port, and the
    /// stale one can win. Asserting only "the install succeeded" would pass with the deregistration
    /// at any layer — or missing. So both scopes are recorded into ONE shared transcript and the
    /// assertion is that the other-scope DELETE precedes the target-scope CREATE.
    #[test]
    fn install_deregisters_the_other_scope_before_creating_at_the_requested_one() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let target = MockBackend::tagged("system:", &log, false);
        let stale_user = MockBackend::tagged("user:", &log, true);

        let (report, migration) =
            install_at_scope(&target, Some((&stale_user, ServiceScope::User)), &plan())
                .expect("install proceeds after migrating the other scope");

        assert!(report.created, "the requested scope is registered");
        let migration = migration.expect("a migration was attempted");
        assert_eq!(migration.scope, ServiceScope::User);
        assert!(migration.found && migration.removed, "{migration:?}");
        assert!(migration.error.is_none());

        let calls = target.calls();
        let user_delete = calls
            .iter()
            .position(|c| c == "user:delete")
            .expect("the stale user-scope registration is deleted");
        let system_create = calls
            .iter()
            .position(|c| c == "system:create")
            .expect("the requested system-scope registration is created");
        assert!(
            user_delete < system_create,
            "the other scope must be deregistered BEFORE creating at the requested scope, \
             or both registrations coexist and the stale one can win: {calls:?}"
        );
        // The stale unit is stopped before it is deleted, so nothing keeps holding the port.
        let user_stop = calls.iter().position(|c| c == "user:stop").unwrap();
        assert!(user_stop < user_delete, "{calls:?}");
    }

    #[test]
    fn install_touches_nothing_at_the_other_scope_when_it_holds_no_registration() {
        // The common fresh install: probing the other scope is READ-ONLY, so an absent
        // registration must not produce a stop/delete (which would surface spurious errors on
        // every desktop install).
        let log = Rc::new(RefCell::new(Vec::new()));
        let target = MockBackend::tagged("system:", &log, false);
        let other = MockBackend::tagged("user:", &log, false);

        let (report, migration) =
            install_at_scope(&target, Some((&other, ServiceScope::User)), &plan()).unwrap();

        assert!(report.created);
        let migration = migration.expect("a migration was attempted");
        assert!(!migration.found && !migration.removed);
        let calls = target.calls();
        assert!(
            !calls.iter().any(|c| c == "user:delete" || c == "user:stop"),
            "no write at an unregistered scope: {calls:?}"
        );
    }

    #[test]
    fn install_still_succeeds_when_the_other_scope_cannot_be_deregistered() {
        // Best-effort: an unprivileged user cannot delete a system unit. That must be REPORTED,
        // not fatal — the requested (user-scope) registration still goes in.
        let log = Rc::new(RefCell::new(Vec::new()));
        let target = MockBackend::tagged("user:", &log, false);
        let other = MockBackend::tagged("system:", &log, true).failing_delete();

        let (report, migration) =
            install_at_scope(&target, Some((&other, ServiceScope::System)), &plan())
                .expect("a failed other-scope removal must not fail the install");

        assert!(report.created);
        let migration = migration.expect("a migration was attempted");
        assert!(migration.found && !migration.removed);
        assert!(
            migration.error.is_some(),
            "an un-removable stale registration is reported, never silently dropped"
        );
    }

    #[test]
    fn install_with_no_other_scope_reports_no_migration() {
        // Windows: SCM has exactly one scope, so there is no other scope to migrate FROM.
        let target = MockBackend::new(false);
        let (report, migration) =
            install_at_scope(&target, None::<(&MockBackend, ServiceScope)>, &plan()).unwrap();
        assert!(report.created);
        assert!(migration.is_none());
    }

    // -- #526 uninstall: remove at the requested scope, both under `auto` as root -------------

    #[test]
    fn uninstall_scopes_cover_both_scopes_under_auto_and_only_the_named_one_otherwise() {
        use ScopeChoice::{Auto, System as ChooseSystem, User as ChooseUser};
        use ServiceScope::{System, User};

        // `auto` sweeps BOTH scopes so an uninstall can never leave a registration behind
        // (the #1863 defect class), requested scope first.
        assert_eq!(uninstall_scopes(Auto, true, true), vec![System, User]);
        assert_eq!(uninstall_scopes(Auto, true, false), vec![User, System]);
        // An explicit choice removes exactly what was named.
        assert_eq!(uninstall_scopes(ChooseSystem, true, false), vec![System]);
        assert_eq!(uninstall_scopes(ChooseUser, true, true), vec![User]);
        // An OS with one scope has one thing to remove, whatever was asked for.
        assert_eq!(uninstall_scopes(Auto, false, false), vec![System]);
        assert_eq!(uninstall_scopes(ChooseUser, false, false), vec![System]);
    }

    #[test]
    fn uninstall_removes_every_scope_that_holds_a_registration() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let system = MockBackend::tagged("system:", &log, true);
        let user = MockBackend::tagged("user:", &log, true);
        let removals = remove_registrations(&[
            (&system, ServiceScope::System, RemovalMode::Requested),
            (&user, ServiceScope::User, RemovalMode::Swept),
        ]);

        assert_eq!(removals.len(), 2);
        assert!(
            removals.iter().all(|r| r.found && r.removed),
            "{removals:?}"
        );
        let outcome = uninstall_outcome(removals).expect("removing both scopes is a success");
        assert_eq!(outcome.result["registered"], json!(false));
        assert_eq!(outcome.result["removed_scopes"], json!(["system", "user"]));
    }

    #[test]
    fn uninstall_fails_loudly_when_a_found_registration_could_not_be_removed() {
        // The #1863 defect class: a leftover registration reported as success. One scope removes
        // cleanly and the OTHER fails — an outcome-only assertion ("it errored") would pass even
        // if the successful scope had never been attempted, so both halves are asserted.
        let log = Rc::new(RefCell::new(Vec::new()));
        let user = MockBackend::tagged("user:", &log, true);
        let system = MockBackend::tagged("system:", &log, true).failing_delete();
        let removals = remove_registrations(&[
            (&user, ServiceScope::User, RemovalMode::Requested),
            (&system, ServiceScope::System, RemovalMode::Swept),
        ]);

        assert!(removals[0].removed, "the removable scope IS removed");
        assert!(removals[1].found && !removals[1].removed);
        let err = uninstall_outcome(removals)
            .expect_err("a registration left behind must not be reported as success");
        let msg = err.to_string();
        assert!(msg.contains("system"), "names the scope left behind: {msg}");
        assert!(msg.contains("user"), "reports what WAS removed too: {msg}");
    }

    #[test]
    fn uninstall_reports_an_indeterminate_scope_rather_than_assuming_it_is_clean() {
        // A probe that errors is NOT evidence of absence — fail closed and say so.
        let backend = MockBackend::new(true).failing_probe().failing_delete();
        let removals =
            remove_registrations(&[(&backend, ServiceScope::System, RemovalMode::Requested)]);
        assert!(!removals[0].found, "the probe reported nothing");
        assert!(!removals[0].removed, "the removal did not succeed either");
        assert!(
            removals[0].indeterminate,
            "absence was never established, so the scope is UNKNOWN: {removals:?}"
        );
        let err = uninstall_outcome(removals)
            .expect_err("an unresolved scope must not be reported as a clean uninstall");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn uninstall_errors_when_no_scope_holds_a_registration() {
        // Genuine absence: the probe sees nothing AND the OS itself reports NotFound on removal.
        // (A removal that fails for any OTHER reason is `indeterminate`, not absence — B4.)
        let backend = MockBackend::new(false).failing_delete_not_found();
        let removals =
            remove_registrations(&[(&backend, ServiceScope::User, RemovalMode::Requested)]);
        let err = uninstall_outcome(removals).expect_err("nothing to uninstall is an error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// Regression test for the real macOS `service-smoke` failure this change first caused: the
    /// runner had a user-scope agent registered, but `launchctl print gui/<uid>/<label>` cannot see
    /// it from a session with no GUI domain, so a probe-GATED uninstall reported
    /// `no service registration … was found` and exited 6 on a service that WAS registered.
    ///
    /// The scope the operator NAMED must therefore be deregistered without trusting the probe — the
    /// OS removal call is the authority. The mock is built with the lying combination (`installed:
    /// false` for the probe, but a `delete` that succeeds), which is exactly what a false-negative
    /// launchd probe looks like from here.
    #[test]
    fn a_requested_scope_is_removed_even_when_the_probe_cannot_see_it() {
        let backend = MockBackend::new(false); // probe says "nothing here" — and is wrong
        let removal = remove_registration(&backend, ServiceScope::User, RemovalMode::Requested);

        assert!(
            !removal.found,
            "the probe false-negatived, as launchd's does"
        );
        assert!(
            removal.removed,
            "the deregistration must be attempted anyway, and it succeeded: {removal:?}"
        );
        assert!(!removal.indeterminate);
        assert!(
            backend.calls().contains(&"delete".to_string()),
            "delete must be called despite the probe: {:?}",
            backend.calls()
        );
        let outcome = uninstall_outcome(vec![removal]).expect("a proven removal is a success");
        assert_eq!(outcome.result["removed_scopes"], json!(["user"]));
    }

    /// The structural gap the review named (#526/B3): every migration test used a mock whose probe
    /// answers TRUTHFULLY, so the suite proved the ORDER of the sweep but never its VISIBILITY. As
    /// root the OS probe CANNOT see another account's user-scope registration — systemd has no
    /// `--user` session for root, and `gui/<uid>` is uid 0's domain — so a probe-gated sweep is a
    /// silent no-op exactly when it matters. This asserts what the OS-manager sweep does in that
    /// state (nothing, invisibly), which is WHY the filesystem sweep exists.
    #[test]
    fn a_swept_scope_is_invisible_to_the_probe_when_a_registration_does_exist_b3() {
        // The lying combination: a registration IS present, but the probe (as root) reports false.
        let backend = MockBackend::new(false);
        let removal = remove_registration(&backend, ServiceScope::User, RemovalMode::Swept);

        assert!(!removal.found && !removal.removed);
        assert!(
            !removal.indeterminate,
            "the probe answered cleanly — it just answered WRONGLY, which no probe-gated sweep can \
             detect: {removal:?}"
        );
        assert_eq!(
            backend.calls(),
            vec!["is_installed"],
            "nothing was even attempted, and nothing was reported — hence the filesystem sweep"
        );
        // So the account-aware mechanism must NOT be probe-gated, and must state its own residual
        // rather than implying completeness.
        let note = crate::user_scope::UserScopeSweep::residual_note();
        assert!(
            note.contains("XDG_CONFIG_HOME"),
            "the residual must be stated, not implied: {note}"
        );
    }

    #[test]
    fn a_swept_scope_is_never_written_to_on_a_probe_that_sees_nothing() {
        // The counterpart: the requested/swept distinction is what keeps the unconditional removal
        // above from also disturbing a scope nobody asked about. Same mock, opposite mode.
        let backend = MockBackend::new(false);
        let removal = remove_registration(&backend, ServiceScope::System, RemovalMode::Swept);

        assert!(!removal.removed && !removal.indeterminate);
        assert_eq!(
            backend.calls(),
            vec!["is_installed"],
            "a swept scope is probed and then left alone"
        );
    }

    // -- #526/B2: no control character may reach a root-owned unit file ----------------------

    /// The unit-file injection guard. `service-manager`'s systemd backend writes each baked variable
    /// as one raw `Environment="K=V"` line into a ROOT-owned unit, unescaped — so a value carrying a
    /// newline appends directives (`ExecStartPre=` may appear repeatedly and runs as root before
    /// `ExecStart`). The fixture uses the real reachable carrier, `DIG_RPC_UPSTREAM`, whose value can
    /// come from a `config.json` under a user-writable `$HOME`.
    #[test]
    fn a_control_character_in_a_baked_env_value_is_refused_for_system_scope_b2() {
        let injected = "https://a.test\nExecStartPre=/tmp/pwn\n";
        let env = vec![("DIG_RPC_UPSTREAM".to_string(), injected.to_string())];

        let err = ensure_environment_is_unit_file_safe(&env, ServiceScope::System)
            .expect_err("a newline in a value written into a root unit file must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(
            msg.contains("DIG_RPC_UPSTREAM"),
            "names the variable: {msg}"
        );
        assert!(
            msg.contains("control character"),
            "states the guard over the CLASS, not one directive: {msg}"
        );
    }

    #[test]
    fn every_control_character_class_is_refused_in_a_key_or_a_value_b2() {
        // The guard is over the class: \n (new directive), \r (systemd also splits on CR), \0
        // (truncation). In the KEY as well as the VALUE — the key is written on the same line.
        for bad in ["\n", "\r", "\0"] {
            let in_value = vec![("DIG_NODE_CACHE".to_string(), format!("/tmp{bad}Bad=1"))];
            assert!(
                ensure_environment_is_unit_file_safe(&in_value, ServiceScope::System).is_err(),
                "{bad:?} in a value must be refused"
            );
            let in_key = vec![(format!("DIG_NODE_CACHE{bad}Bad"), "/tmp".to_string())];
            assert!(
                ensure_environment_is_unit_file_safe(&in_key, ServiceScope::System).is_err(),
                "{bad:?} in a key must be refused"
            );
        }
        // A clean environment passes — the guard must not reject the ordinary case (otherwise every
        // install would fail and the tests above would prove nothing about the guard's precision).
        let clean =
            build_plan(&Config::default(), PathBuf::from("/opt/dig/bin/dig-node")).environment;
        assert!(ensure_environment_is_unit_file_safe(&clean, ServiceScope::System).is_ok());
    }

    #[test]
    fn user_scope_does_not_apply_the_unit_file_guard_b2() {
        // A user-scope unit is written by, and runs as, the very user who owns these values — no
        // privilege boundary is crossed, so the guard would only reject that user's own footgun.
        let env = vec![("DIG_RPC_UPSTREAM".to_string(), "https://a\nb".to_string())];
        assert!(ensure_environment_is_unit_file_safe(&env, ServiceScope::User).is_ok());
    }

    #[test]
    fn a_control_character_never_survives_upstream_normalisation_b2() {
        // Source-side rejection, so a poisoned value cannot even PERSIST into config.json and be
        // baked at some later install.
        assert!(crate::config::contains_control_character(
            "https://a\nExecStartPre=/tmp/x"
        ));
        assert!(crate::config::normalize_upstream("https://a\nExecStartPre=/tmp/x").is_empty());
        // The ordinary value is untouched.
        assert_eq!(
            crate::config::normalize_upstream("rpc.dig.net"),
            "https://rpc.dig.net"
        );
    }

    // -- #526/B4: a failed removal is never reported as "nothing was installed" ---------------

    #[test]
    fn a_removal_that_fails_for_any_reason_but_absence_is_indeterminate_b4() {
        // The classification: only the OS positively saying NotFound means "there was nothing here".
        assert!(
            !removal_failure_is_indeterminate(false, io::ErrorKind::NotFound),
            "a readable probe plus NotFound is genuine absence"
        );
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
            io::ErrorKind::TimedOut,
        ] {
            assert!(
                removal_failure_is_indeterminate(false, kind),
                "{kind:?} leaves a possible registration behind and MUST be unresolved"
            );
        }
        // An unreadable probe is unknown regardless of what the delete then said.
        assert!(removal_failure_is_indeterminate(
            true,
            io::ErrorKind::NotFound
        ));
    }

    /// The macOS-from-the-other-side case: an ssh session with no Aqua domain false-negatives the
    /// probe AND fails `unload` before the plist is removed. Reporting `NotFound` there would tell
    /// the operator nothing was installed while the agent still starts at next login.
    #[test]
    fn a_failed_removal_is_not_reported_as_nothing_to_uninstall_b4() {
        let backend = MockBackend::new(false).failing_delete(); // probe lies, delete denied
        let removal = remove_registration(&backend, ServiceScope::User, RemovalMode::Requested);
        assert!(!removal.found && !removal.removed);
        assert!(
            removal.indeterminate,
            "a PermissionDenied removal leaves the state UNKNOWN: {removal:?}"
        );
        let err = uninstall_outcome(vec![removal]).expect_err("must not be a success");
        assert_ne!(
            err.kind(),
            io::ErrorKind::NotFound,
            "telling the operator 'nothing to uninstall' would be a lie: {err}"
        );
    }

    /// The multi-scope shape of the same defect: one scope removed, another left behind. A
    /// `removed`-only classification would report plain success.
    #[test]
    fn a_leftover_at_one_scope_is_not_masked_by_a_success_at_another_b4() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let user = MockBackend::tagged("user:", &log, true);
        let system = MockBackend::tagged("system:", &log, false).failing_delete();
        let removals = remove_registrations(&[
            (&user, ServiceScope::User, RemovalMode::Requested),
            (&system, ServiceScope::System, RemovalMode::Requested),
        ]);
        assert!(removals[0].removed, "one scope genuinely removed");
        assert!(removals[1].indeterminate, "the other is unknown");
        assert!(uninstall_outcome(removals).is_err());
    }

    #[test]
    fn the_real_backend_can_report_an_unreadable_probe_b4() {
        // `is_installed` must PROPAGATE a probe failure rather than swallow it into `false`, or the
        // `indeterminate` state advertised in SPEC would be unreachable outside the mock. Asserted
        // through the signature: a swallowing implementation cannot express an Err at all.
        fn assert_propagates<F: Fn(&str, ServiceScope) -> io::Result<bool>>(_f: F) {}
        assert_propagates(query_installed);
    }

    // -- #526/B6 + B7: the file's own owner, and an override that cannot be inherited ---------

    /// Directory permissions stop unlink/rename; they do NOT stop a rewrite of a file whose own mode
    /// permits it. A root-owned `0755 /opt/dig/bin` holding a uid-1000 `dig-node` would otherwise
    /// PASS and give that user root at next boot. Table-driven over both independent checks.
    #[test]
    fn the_program_file_must_be_privileged_in_its_own_right_b6() {
        let level = std::path::Path::new("/opt/dig/bin");
        assert_eq!(classify_system_target(None, true), None, "both checks pass");
        assert_eq!(
            classify_system_target(None, false),
            Some(TargetRefusal::ProgramFile),
            "a privileged directory chain does NOT excuse a user-writable program file"
        );
        assert_eq!(
            classify_system_target(Some(level), true),
            Some(TargetRefusal::Directory(level.to_path_buf()))
        );
        assert_eq!(
            classify_system_target(Some(level), false),
            Some(TargetRefusal::Directory(level.to_path_buf())),
            "the wider problem is reported first"
        );
        // Each refusal must be actionable and distinguishable in the message.
        assert!(TargetRefusal::ProgramFile
            .describe()
            .contains("program file"));
        assert!(TargetRefusal::Directory(level.to_path_buf())
            .describe()
            .contains("/opt/dig/bin"));
    }

    #[test]
    fn the_insecure_override_is_inert_for_a_root_system_registration_b7() {
        // The env var is INHERITABLE (`sudo -E`, a root profile export, a CI value leaking into an
        // operator shell). It must not be able to switch the §565 gate off for a root boot daemon.
        assert!(
            !insecure_override_is_effective(true, ServiceScope::System, true),
            "a genuinely-root system registration must ignore the override"
        );
        // …and must still work where it is legitimately needed.
        assert!(insecure_override_is_effective(
            true,
            ServiceScope::System,
            false
        ));
        assert!(insecure_override_is_effective(
            true,
            ServiceScope::User,
            true
        ));
        // Absent env var ⇒ never effective (default-safe).
        assert!(!insecure_override_is_effective(
            false,
            ServiceScope::System,
            false
        ));
    }

    // -- #526: the §565 gate now fires on unix system scope, so its refusal must be actionable

    #[test]
    fn a_refused_system_target_names_the_offending_directory_level() {
        // The gate walks EVERY ancestor, so the leaf is often fine while a parent is not. An
        // operator cannot act on "somewhere in this path is user-writable" — the refusal must name
        // the level that failed. A nested tempdir gives a leaf whose PARENT chain is user-owned.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("bin");
        std::fs::create_dir(&nested).unwrap();
        let program = nested.join("dig-node");

        let err = ensure_service_target_is_safe(&program, ServiceScope::System, false)
            .expect_err("a system-level install from an unprivileged target must be refused");
        let msg = err.to_string();

        // WHICH check fires depends on the host and on whether the suite itself runs as root (a
        // root-owned temp dir clears the directory chain, leaving the FILE check to refuse), so the
        // test asserts against the classifier's own verdict for this exact path rather than assuming
        // one of them — otherwise it would false-RED under `sudo cargo test` and, worse, stop
        // testing a refusal at all.
        let expected = classify_system_target(
            crate::security::first_unprivileged_ancestor(&nested),
            crate::security::file_is_privileged(&program),
        )
        .expect("an unprivileged target must classify as a refusal");
        // A bare `contains(<some ancestor path>)` would be VACUOUS: every ancestor is a string
        // PREFIX of the program path the message already prints, so it would hold even if nothing
        // were named. Assert the exact naming PHRASE the refusal is required to carry.
        assert!(
            msg.contains(&expected.describe()),
            "the refusal must name what failed ({}): {msg}",
            expected.describe()
        );
    }
}
