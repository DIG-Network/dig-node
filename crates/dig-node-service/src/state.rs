//! The machine-wide DAEMON STATE directory — where the node's control/auth state
//! (the control token + the paired-token store) lives, resolved IDENTICALLY by the
//! running daemon AND the operator CLI regardless of which OS user each runs as
//! (#501).
//!
//! # Why this exists (the bug it fixes)
//!
//! The bulk per-user cache ([`dig_node_core::cache_dir`], `%LOCALAPPDATA%\DigNode\cache`
//! / `$HOME/DigNode/cache`) and the node `config.json` beside it are resolved from the
//! RUNNING PROCESS's identity. That is correct for the shared `.dig` cache (#96), but it
//! breaks the control token: on a real install the node runs as the Windows
//! **LocalSystem** service, so it writes `control-token` under
//! `C:\Windows\System32\config\systemprofile\AppData\Local\DigNode\` — a path the
//! interactive user's `dig-node pair` can neither read nor even resolve (the user's
//! `%LOCALAPPDATA%` is `C:\Users\<u>\AppData\Local`). The CLI then MINTS a different
//! token the running node never trusts, so every `control.*` / `dig-node pair` call
//! fails `-32030 UNAUTHORIZED`. The same split happens on Linux/macOS when the daemon
//! runs as root/a service account and the operator is a normal user.
//!
//! # The fix
//!
//! A machine-wide, identity-INDEPENDENT [`state_dir`] holds ONLY the control/auth state
//! (control token + `paired-tokens.json`). Because it does not depend on `%LOCALAPPDATA%`
//! / `$HOME`, the daemon and the CLI resolve the SAME directory and read the SAME token.
//! The bulk `cache_dir` and `config.json` are UNCHANGED (they stay per-user + shared with
//! the browser/digstore, #96) — only the small security-critical auth state moves here.
//!
//! # Layout (per OS)
//!
//! - **Windows:** `%PROGRAMDATA%\DigNode` (`C:\ProgramData\DigNode`).
//! - **macOS:** `/Library/Application Support/DigNode`.
//! - **Linux:** `/var/lib/dig-node`, falling back to `/etc/dig-node` when the former is
//!   not creatable/writable.
//! - **Env override** `DIG_NODE_STATE_DIR` — for tests + custom deploys; wins outright.
//! - **Dev fallback** — a non-service `dig-node run` as a normal user, with no machine-wide
//!   dir present, uses the LEGACY per-user dir ([`legacy_state_dir`]) so existing dev
//!   workflows keep working. (Additive: nothing that worked before breaks.)
//!
//! # Security (the crux — the #501 hardening contract, [`harden_state_dir`])
//!
//! The control token grants FULL local control of the node (mint controller tokens,
//! change pins, drive wallet-adjacent control). A machine-wide file must therefore NOT be
//! world/all-users-readable, or ANY local user could seize control — a local privilege
//! escalation.
//!
//! On Windows this is the HARD case: `%PROGRAMDATA%` grants `BUILTIN\Users` "create
//! subfolder", so ANY low-priv user can pre-create `C:\ProgramData\DigNode` and become its
//! CREATOR OWNER — and an owner keeps `WRITE_DAC` forever, so a naive
//! `icacls /inheritance:r /grant:r` (which never resets OWNER and never purges foreign
//! explicit ACEs) leaves the squatter able to rewrite the DACL and read the daemon's
//! control token. A pre-existing dir must NOT be trusted blindly. On a SERVICE run,
//! BEFORE the daemon writes/reads the control token, the resolved MACHINE state dir is
//! therefore HARDENED + READBACK-VERIFIED ([`ensure_service_state_dir`] →
//! [`harden_state_dir`]): a squatter-owned dir is purged, owner is forced to SYSTEM
//! (`icacls /setowner *S-1-5-18 /T`), all foreign explicit ACEs are dropped
//! (`icacls /reset /T`), and a PROTECTED DACL of exactly {SYSTEM:F, Administrators:F,
//! and — only if discoverable — the interactive install-user:R} is applied
//! (`icacls /inheritance:r /grant:r …` by SID), then the ACL is read back and asserted:
//! owner is SYSTEM, inheritance is OFF, NO Everyone/Users/Authenticated-Users ACE, and only
//! the granted principals are present. If any step fails, [`harden_state_dir`] FAILS CLOSED
//! (returns `Err`) — the caller deletes the dir and refuses to serve the control plane from
//! it (falling back to an unusable in-memory token) rather than writing the token into an
//! unsecured dir.
//!
//! A SYSTEM/root service must NOT clobber a legit installer-set ACL that grants the
//! interactive install-user READ. Idempotency reconciles this: SYSTEM + Administrators are
//! granted full always, and an interactive read grant is preserved/re-added only when it is
//! DISCOVERABLE on a TRUSTED (SYSTEM/Administrators-owned) pre-existing dir. The security
//! invariant that holds EITHER way is: NO Users/Everyone/Authenticated-Users ACE and
//! owner = SYSTEM.
//!
//! On Unix the dir is `0700` and the token file `0600`, owned by the daemon identity (root
//! on a real install under root-owned `/var/lib`, which is not squattable). The CLI
//! (non-service) NEVER hardens — it only READS an existing machine dir, else falls back to
//! the legacy per-user dir. A non-service dev run on the legacy per-user dir does NOT invoke
//! the machine-dir hardening (that dir is already user-scoped).

use std::path::{Path, PathBuf};

/// The env var that overrides the resolved state dir outright (tests + custom deploys).
pub const STATE_DIR_ENV: &str = "DIG_NODE_STATE_DIR";

/// The env var the INSTALLED service carries so it self-identifies as a service run
/// (set by `dig-node install` into the service environment, and by the Windows SCM
/// entrypoint at runtime). Only a service run may CREATE + HARDEN the machine-wide dir when
/// it is absent; the CLI never does (it only reads an existing one, else the legacy dir).
pub const RUN_CONTEXT_ENV: &str = "DIG_NODE_RUN_CONTEXT";

/// The value of [`RUN_CONTEXT_ENV`] that marks a service run.
pub const RUN_CONTEXT_SERVICE: &str = "service";

/// The machine-wide base folder name (Windows/macOS) — `DigNode` under `%PROGRAMDATA%` /
/// `/Library/Application Support`. Linux uses the kebab `dig-node` path directly, so this is
/// only referenced on Windows + macOS (gated to avoid a dead-code lint on Linux).
#[cfg(any(windows, target_os = "macos"))]
const MACHINE_FOLDER: &str = "DigNode";

// ---------------------------------------------------------------------------
// Well-known SIDs (locale-independent — icacls / Get-Acl accept + emit these).
// ---------------------------------------------------------------------------

/// LocalSystem — the daemon identity + the forced owner of the state dir.
const SID_SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators.
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// Everyone.
const SID_EVERYONE: &str = "S-1-1-0";
/// Authenticated Users.
const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
/// Anonymous Logon.
const SID_ANONYMOUS: &str = "S-1-5-7";
/// BUILTIN\Users.
const SID_USERS: &str = "S-1-5-32-545";

/// The ordered machine-wide candidate directories for THIS OS (identity-independent).
/// The first that already exists wins; a service run may create the first creatable one.
/// PURE except for reading `%PROGRAMDATA%` on Windows (an env that does not vary by user).
pub fn machine_state_dirs() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var("PROGRAMDATA")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| r"C:\ProgramData".to_string());
        vec![PathBuf::from(base).join(MACHINE_FOLDER)]
    }
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from("/Library/Application Support").join(MACHINE_FOLDER)]
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Linux (and other Unix): the FHS machine-state dir, then a common fallback.
        vec![
            PathBuf::from("/var/lib/dig-node"),
            PathBuf::from("/etc/dig-node"),
        ]
    }
}

/// Is `dir` one of THIS OS's machine-wide state candidates? Only a machine dir is
/// hardened (the legacy per-user dir is already user-scoped and a custom `DIG_NODE_STATE_DIR`
/// override — e.g. a test temp dir — must NOT be purged/hardened). PURE given
/// [`machine_state_dirs`].
pub fn is_machine_state_dir(dir: &Path) -> bool {
    machine_state_dirs().iter().any(|c| c == dir)
}

/// The LEGACY per-user state dir used before #501 (and still used for a non-service dev
/// run): the parent of the node `config.json` (`%LOCALAPPDATA%\DigNode` /
/// `$HOME/DigNode`). Kept as the back-compat fallback so an existing `dig-node run` as a
/// normal user finds its old control token unchanged.
pub fn legacy_state_dir() -> PathBuf {
    let config = dig_node_core::config_path();
    config
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Whether THIS process is the installed service (so it may create + harden the machine-wide
/// dir when absent). Driven by [`RUN_CONTEXT_ENV`] — set by `dig-node install` into the
/// service environment and by the Windows SCM entrypoint at runtime — so the CLI (which
/// never carries it) is never treated as a service.
pub fn running_as_service() -> bool {
    std::env::var(RUN_CONTEXT_ENV)
        .ok()
        .map(|v| v.trim().eq_ignore_ascii_case(RUN_CONTEXT_SERVICE))
        .unwrap_or(false)
}

/// PURE decision core (no I/O): pick the state dir from the inputs, so the priority is
/// unit-testable without touching the real filesystem/env.
///
/// Priority: explicit `override_dir` › the first machine candidate that already EXISTS
/// (daemon + CLI agree via the shared filesystem) › for a SERVICE run, the first machine
/// candidate that can be created › the legacy per-user dir (dev fallback).
fn choose_state_dir(
    override_dir: Option<PathBuf>,
    machine_candidates: &[PathBuf],
    exists: &dyn Fn(&Path) -> bool,
    can_create: &dyn Fn(&Path) -> bool,
    is_service: bool,
    legacy: PathBuf,
) -> PathBuf {
    if let Some(dir) = override_dir {
        return dir;
    }
    // A machine dir that already exists is authoritative for EVERYONE on the box: the
    // installer or a prior service run created it, and daemon + CLI see the same disk.
    for c in machine_candidates {
        if exists(c) {
            return c.clone();
        }
    }
    // Only the service may bootstrap the machine dir when it is absent — the CLI must not
    // (a normal-user `dig-node pair` should never seed a machine-wide dir; it falls back
    // to the legacy per-user dir it always used).
    if is_service {
        for c in machine_candidates {
            if can_create(c) {
                return c.clone();
            }
        }
    }
    legacy
}

/// The resolved machine-wide state dir for this process (see the module docs). Wires the
/// real filesystem/env into [`choose_state_dir`]. This is a PATH resolver only: it does NOT
/// harden a pre-existing machine dir (that is the SERVICE-only [`ensure_service_state_dir`]
/// chokepoint — the CLI must never attempt to harden, being non-elevated). A service run
/// that must BOOTSTRAP an absent machine dir creates the first creatable candidate here; the
/// authoritative harden + readback-verify then runs in [`ensure_service_state_dir`].
pub fn state_dir() -> PathBuf {
    let override_dir = std::env::var(STATE_DIR_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let candidates = machine_state_dirs();
    let is_service = running_as_service();
    let exists = |p: &Path| p.is_dir();
    // "Can create" = we successfully created it (a restrictive best-effort ACL is applied on
    // fresh create; the authoritative harden runs in `ensure_service_state_dir`).
    let can_create = |p: &Path| ensure_dir_restricted(p).is_ok() && is_dir_writable(p);
    choose_state_dir(
        override_dir,
        &candidates,
        &exists,
        &can_create,
        is_service,
        legacy_state_dir(),
    )
}

/// The SERVICE-run chokepoint (#501 P0): resolve the state dir and, when it is a MACHINE
/// dir, HARDEN + readback-VERIFY it per the security contract BEFORE the control token is
/// written into it. Returns the secured dir, or an `Err` when a machine dir cannot be
/// secured — in which case the caller MUST refuse to serve the control plane from it (write
/// nothing there; fall back to an unusable in-memory token).
///
/// A resolved LEGACY per-user dir (a user-level service that could not create `/var/lib`)
/// is already user-scoped, so it is only created (not hardened) — the daemon and that same
/// user's CLI still agree on it. MUST be called only on a service run (`debug_assert`ed).
pub fn ensure_service_state_dir() -> std::io::Result<PathBuf> {
    debug_assert!(
        running_as_service(),
        "ensure_service_state_dir is a service-only chokepoint"
    );
    let dir = state_dir();
    if is_machine_state_dir(&dir) {
        let read_grant = service_read_grant(&dir);
        harden_state_dir(&dir, read_grant.as_deref())?;
    } else {
        // Legacy per-user (or override) dir — already user-scoped; just ensure it exists.
        ensure_dir_restricted(&dir)?;
    }
    Ok(dir)
}

/// The read-grant principal for a SERVICE harden of `dir`: the interactive install-user's
/// SID that should retain READ access to the control token.
///
/// 1. The CURRENT PROCESS TOKEN's user SID — but only when it is a REAL interactive user
///    (a `dig-node install` run as the interactive admin). On a LocalSystem service this is
///    SYSTEM (a forbidden grant) ⇒ `None`.
/// 2. Otherwise, PRESERVE an installer-set interactive grant already discoverable on a
///    TRUSTED (SYSTEM/Administrators-owned) pre-existing dir, so a later SYSTEM service run
///    does not strip the operator's read ACE.
/// 3. Else `None` — SYSTEM + Administrators only; a non-elevated operator CLI then needs
///    elevation (surfaced via the precise remedy).
#[cfg(windows)]
fn service_read_grant(dir: &Path) -> Option<String> {
    if let Some(sid) = current_user_sid() {
        return Some(sid);
    }
    discover_existing_read_grant(dir)
}

/// Non-Windows: no ACL read-grant principal (Unix uses mode bits + a best-effort installer
/// `setfacl`, handled by the installer, not here).
#[cfg(not(windows))]
fn service_read_grant(_dir: &Path) -> Option<String> {
    None
}

/// The interactive read-grant SID for a `dig-node install` harden (the installing user, from
/// the process token). `None` on non-Windows and when the process token is SYSTEM / a
/// forbidden group. Used by [`crate::service`] to grant the operator READ so a later SYSTEM
/// service run can PRESERVE that grant (via [`service_read_grant`] discovery on the
/// SYSTEM-owned dir).
#[cfg(windows)]
pub fn interactive_read_grant() -> Option<String> {
    current_user_sid()
}

/// Non-Windows: the interactive grant is expressed via the installer's `setfacl`, not here.
#[cfg(not(windows))]
pub fn interactive_read_grant() -> Option<String> {
    None
}

/// Is `dir` writable? Probes with a unique temp file (created + removed). Used so a
/// service run only claims a machine candidate it can actually write the token into.
fn is_dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".dig-state-probe-{}", std::process::id()));
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Ensure `dir` exists with a best-effort restrictive ACL — the create-path helper used
/// during resolution ([`state_dir`]), by `dig-node install` pre-create, and by the token /
/// paired-token writers. It is NOT the authoritative security gate: a pre-existing dir is
/// trusted as-is (early return) so a SYSTEM/root service does not clobber the installer's
/// interactive read grant. The AUTHORITATIVE harden + readback-verify of a machine dir on a
/// service run is [`ensure_service_state_dir`] / [`harden_state_dir`].
///
/// On a fresh create: Unix `0700`; Windows a best-effort inheritable grant to SYSTEM +
/// Administrators (+ the creating REAL user, by process-token SID). Best-effort on the ACL
/// step (a tighten failure must not hard-fail this path — the loopback bind + token
/// possession + the service-run harden are the primary gates); the `create_dir_all` is
/// surfaced so a caller can fall back to another candidate.
pub fn ensure_dir_restricted(dir: &Path) -> std::io::Result<()> {
    // Already present ⇒ trust its ACL here (the installer, a prior run, or the service-run
    // harden established it). Do NOT re-tighten: a SYSTEM/root service re-applying an ACL via
    // this best-effort path would drop the interactive user's explicit read grant.
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(windows)]
    {
        windows_grant_best_effort(dir);
    }
    Ok(())
}

/// Restrict a control/auth FILE (the control token, the paired-token store) so it is NOT
/// readable by every local user.
///
/// - **Unix:** set the file to `0600` (owner read/write only) — the CI-gated assertion path.
/// - **Windows:** a NO-OP by design. The file INHERITS the tight, inheritable ACL of its
///   parent state dir (established by the service-run harden, [`harden_state_dir`], or the
///   installer), which is where the security boundary lives. Re-applying an explicit
///   `icacls /inheritance:r` here would be actively harmful: when the daemon runs as SYSTEM it
///   would grant only SYSTEM/Administrators and STRIP the interactive install-user's inherited
///   read ACE, re-breaking #501 for the operator CLI. A freshly-created file under the
///   restricted dir is already non-world-readable via inheritance.
///
/// Best-effort (a perms failure is ignored — the loopback bind + token possession are the
/// primary gate; the dir ACL is defense-in-depth against local privilege escalation).
pub(crate) fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        // Windows (and other): the parent dir's inheritable ACL governs — see the doc above.
        let _ = path;
    }
}

// ---------------------------------------------------------------------------
// The hardening contract (#501): pure argv/parse helpers + the I/O orchestrator.
// The SID parsing, the `icacls` argv builders, and the `Get-Acl` readback parser are
// PURE and unit-tested; the create + ACL calls are the thin I/O layer (real ACL behaviour
// is not exercised in CI, so correctness rests on careful code + the pure-logic tests).
// ---------------------------------------------------------------------------

/// A well-known GROUP / broad SID that must NEVER appear in the control-token dir's DACL
/// (world/broad-group readable = the priv-esc the tight ACL exists to prevent).
pub fn is_dangerous_group_sid(sid: &str) -> bool {
    matches!(
        sid,
        SID_EVERYONE | SID_AUTHENTICATED_USERS | SID_ANONYMOUS | SID_USERS
    )
}

/// May `sid` be the READ-grant principal (the interactive user)? Rejects the dangerous
/// broad groups AND SYSTEM (the interactive identity must be a real user; SYSTEM is the
/// daemon owner, never the interactive grantee). A spoofed `%USERNAME%=Everyone` used to
/// yield `Everyone:(OI)(CI)R` — this is the guard against granting a group.
pub fn is_forbidden_grant_sid(sid: &str) -> bool {
    is_dangerous_group_sid(sid) || sid == SID_SYSTEM
}

/// Parse the interactive-user SID from `whoami /user /fo csv /nh` output —
/// `"domain\user","S-1-5-21-…"`. The SID comes from the process TOKEN (not the spoofable
/// `%USERNAME%`/`%USERDOMAIN%` env), so it cannot be forged by setting `%USERNAME%=Everyone`.
/// Returns the first `S-1-…` field. PURE.
pub fn parse_whoami_csv_sid(text: &str) -> Option<String> {
    text.split([',', '"', '\r', '\n', ' ', '\t'])
        .map(|f| f.trim())
        .find(|f| f.starts_with("S-1-") && f.len() > 6)
        .map(|s| s.to_string())
}

/// `icacls <dir> /setowner *S-1-5-18 /T /C /Q` — force owner = SYSTEM on the dir and every
/// child, defeating a squatter's owner-based `WRITE_DAC`. PURE argv (no shell).
pub fn setowner_system_args(dir: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/setowner".to_string(),
        format!("*{SID_SYSTEM}"),
        "/T".to_string(),
        "/C".to_string(),
        "/Q".to_string(),
    ]
}

/// `icacls <dir> /reset /T /C /Q` — drop ALL explicit ACEs (purging any foreign ACE a
/// squatter added) and restore the parent's inheritable ACEs, so the following
/// `/inheritance:r /grant:r` starts from a known baseline. PURE argv.
pub fn reset_dacl_args(dir: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/reset".to_string(),
        "/T".to_string(),
        "/C".to_string(),
        "/Q".to_string(),
    ]
}

/// `icacls <dir> /inheritance:r /grant:r …` that REPLACES the DACL with exactly
/// {SYSTEM:F, Administrators:F} plus — only when `read_grant` is `Some` — {`read_grant`:R},
/// inheritable to child files (the control-token), inheritance disabled. All principals by
/// SID (locale-independent — the `*S-1-5-18` literal, never the localized name "SYSTEM").
/// The interactive user gets READ only, never full. PURE so the exact ACL is unit-tested.
pub fn windows_lockdown_grant_args(dir: &str, read_grant: Option<&str>) -> Vec<String> {
    let mut args = vec![
        dir.to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        format!("*{SID_SYSTEM}:(OI)(CI)F"),
        "/grant:r".to_string(),
        format!("*{SID_ADMINISTRATORS}:(OI)(CI)F"),
    ];
    if let Some(sid) = read_grant {
        args.push("/grant:r".to_string());
        args.push(format!("*{sid}:(OI)(CI)R"));
    }
    args
}

/// The PowerShell one-liner that emits the dir's owner + each access ACE as SID-based lines
/// (`OWNER;<sid>` / `ACE;<sid>;<isInherited>`) for the readback verification. SID-based (not
/// name-based) so parsing is locale-independent. PURE (single-quotes in the path are doubled
/// for PS literal safety).
pub fn acl_verify_ps_command(dir: &str) -> String {
    let dir = dir.replace('\'', "''");
    format!(
        "$ErrorActionPreference='Stop'; \
         $acl = Get-Acl -LiteralPath '{dir}'; \
         'OWNER;' + $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; \
         foreach ($a in $acl.Access) {{ \
           'ACE;' + $a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value + ';' + $a.IsInherited \
         }}"
    )
}

/// Verify a locked-down DACL from [`acl_verify_ps_command`] output against the acceptance
/// gate (the security contract, step 6). Asserts: owner is SYSTEM (or Administrators); NO
/// inherited ACE (inheritance disabled); NO Everyone/Users/Authenticated-Users/Anonymous
/// ACE; SYSTEM + Administrators are present; and — strictly — NO principal beyond
/// {SYSTEM, Administrators, `read_grant`} is present (a surviving squatter user SID or any
/// unexpected trustee is rejected). When `read_grant` is `Some`, that SID MUST be present.
/// `Err` on any violation. PURE.
pub fn parse_acl_verify(output: &str, read_grant: Option<&str>) -> Result<(), String> {
    let mut owner: Option<String> = None;
    let mut ace_sids: Vec<String> = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("OWNER;") {
            owner = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("ACE;") {
            let mut parts = rest.split(';');
            let sid = parts.next().unwrap_or("").trim().to_string();
            let inherited = parts.next().unwrap_or("").trim();
            if sid.is_empty() {
                continue;
            }
            if inherited.eq_ignore_ascii_case("true") {
                return Err(format!(
                    "inheritance is NOT disabled — inherited ACE present for {sid}"
                ));
            }
            if is_dangerous_group_sid(&sid) {
                return Err(format!(
                    "DACL grants a world/group principal ({sid}) — the token dir must not be group-readable"
                ));
            }
            ace_sids.push(sid);
        }
    }
    let owner = owner.ok_or_else(|| "could not read the directory owner".to_string())?;
    if owner != SID_SYSTEM && owner != SID_ADMINISTRATORS {
        return Err(format!(
            "owner is {owner}, expected SYSTEM ({SID_SYSTEM}) or Administrators ({SID_ADMINISTRATORS})"
        ));
    }
    for required in [SID_SYSTEM, SID_ADMINISTRATORS] {
        if !ace_sids.iter().any(|s| s == required) {
            return Err(format!("DACL is missing the required ACE for {required}"));
        }
    }
    if let Some(sid) = read_grant {
        if !ace_sids.iter().any(|s| s == sid) {
            return Err(format!(
                "DACL is missing the interactive read grant for {sid}"
            ));
        }
    }
    // Strict: nothing beyond the granted principals may remain.
    for sid in &ace_sids {
        let allowed = sid == SID_SYSTEM
            || sid == SID_ADMINISTRATORS
            || read_grant.map(|r| r == sid).unwrap_or(false);
        if !allowed {
            return Err(format!(
                "DACL grants an unexpected principal ({sid}) — only SYSTEM, Administrators, and the interactive read grant are permitted"
            ));
        }
    }
    Ok(())
}

/// From an [`acl_verify_ps_command`] readback of a TRUSTED pre-existing dir, discover an
/// installer-set interactive read grant to PRESERVE: the first ACE SID that is a real
/// per-user domain SID (`S-1-5-21-…`) — i.e. not a well-known/broad group and not
/// SYSTEM/Administrators. `None` if there is none. PURE.
pub fn parse_first_user_read_sid(output: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ACE;") {
            let sid = rest.split(';').next().unwrap_or("").trim();
            if sid.starts_with("S-1-5-21-")
                && sid != SID_SYSTEM
                && sid != SID_ADMINISTRATORS
                && !is_dangerous_group_sid(sid)
            {
                return Some(sid.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Control-token FILE owner verification (#501 residual). A pre-existing token file must be
// OWNED by a trusted principal before the daemon trusts its BYTES: otherwise a local user who
// planted a known token in the (machine-wide) state dir — a `%PROGRAMDATA%` squat, or the
// narrow window during a service harden — could learn the control token and gain full local
// node control (a local privilege escalation). The trust DECISION is a pure, unit-tested
// helper (per platform); the owner READ is the thin I/O in [`token_file_is_trusted`].
// ---------------------------------------------------------------------------

/// PURE: may a control-token FILE whose Windows OWNER is `owner_sid` be trusted (loaded
/// as-is)? SYSTEM (`S-1-5-18`) and Administrators (`S-1-5-32-544`) are ALWAYS trusted (the
/// daemon identity / an elevated installer). A SERVICE run requires one of those — it MUST
/// NEVER trust a token owned by a normal user (that is the priv-esc). A NON-service (dev /
/// operator) run ALSO trusts the CURRENT process user's own SID, so a dev token in the legacy
/// per-user dir keeps working; when the current user SID is indeterminate it stays LENIENT
/// (preserving the pre-#501 dev behaviour) rather than needlessly regenerate. Any OTHER owner
/// (a squatter's SID) is NOT trusted → the file is deleted + regenerated.
#[cfg(windows)]
pub fn windows_token_owner_is_trusted(
    owner_sid: &str,
    is_service: bool,
    current_user_sid: Option<&str>,
) -> bool {
    if owner_sid == SID_SYSTEM || owner_sid == SID_ADMINISTRATORS {
        return true;
    }
    if is_service {
        // A service (LocalSystem) must only trust a SYSTEM/Administrators-owned token.
        return false;
    }
    // Non-service (dev / operator): trust the current user's OWN token; stay lenient when the
    // current user SID is indeterminate (no needless regeneration on a legacy per-user dir).
    match current_user_sid {
        Some(cur) => !cur.is_empty() && owner_sid == cur,
        None => true,
    }
}

/// PURE: may a control-token FILE owned by `owner_uid` with unix `mode` be trusted? `root`
/// (uid 0) is ALWAYS trusted (a root/elevated installer wrote it). Otherwise it is trusted
/// only when owned by the CURRENT effective uid AND `0600` (owner-only) — a token owned by
/// another user, or one any group/other can read, is NOT trusted → deleted + regenerated.
#[cfg(unix)]
pub fn unix_token_owner_is_trusted(owner_uid: u32, mode: u32, current_euid: u32) -> bool {
    if owner_uid == 0 {
        return true;
    }
    owner_uid == current_euid && (mode & 0o777) == 0o600
}

/// Verify a PRE-EXISTING control-token FILE at `path` is owned by a TRUSTED principal before
/// the daemon trusts its contents (#501 residual). `is_service` is the caller's run context
/// ([`running_as_service`]). Returns `true` when the file may be loaded as-is; `false` when it
/// is foreign-owned (a planted/squatted token) and MUST be deleted + regenerated. Reads the
/// real owner (Windows `Get-Acl` via [`path_owner_sid`]; unix `stat`) and defers the decision
/// to the pure [`windows_token_owner_is_trusted`] / [`unix_token_owner_is_trusted`].
pub fn token_file_is_trusted(path: &Path, is_service: bool) -> bool {
    #[cfg(windows)]
    {
        let owner = match path_owner_sid(path) {
            Some(o) => o,
            // Owner indeterminate: fail CLOSED on a service run (security wins over
            // convenience — regenerate); stay LENIENT on a dev run (pre-#501 behaviour).
            None => return !is_service,
        };
        windows_token_owner_is_trusted(&owner, is_service, current_user_sid().as_deref())
    }
    #[cfg(unix)]
    {
        // The unix trust rule is is_service-independent (see the helper): a service runs as
        // root ⇒ its own tokens are uid-0-owned (trusted), and any foreign-uid token is not.
        let _ = is_service;
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        match current_euid_near(path) {
            Some(euid) => unix_token_owner_is_trusted(meta.uid(), meta.mode(), euid),
            // Can't determine our euid → trust only a root-owned file.
            None => meta.uid() == 0,
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (path, is_service);
        true
    }
}

/// The current process's effective uid, via a probe file created in `path`'s parent dir (a
/// freshly-created file is owned by the creating euid). Dependency-free (no `libc`); `None`
/// when the probe cannot be created/statted. Used to compare a token file's owner to "us".
#[cfg(unix)]
fn current_euid_near(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let dir = path.parent()?;
    let probe = dir.join(format!(".dig-euid-probe-{}", std::process::id()));
    std::fs::write(&probe, b"").ok()?;
    let uid = std::fs::metadata(&probe).ok().map(|m| m.uid());
    let _ = std::fs::remove_file(&probe);
    uid
}

/// Harden `dir` per the #501 contract, granting an optional interactive `read_grant`.
/// FAILS CLOSED: any failure to establish + verify the tight ACL returns `Err`, and the
/// caller must delete the dir + refuse to serve control from it. Idempotent on a legit dir
/// (running it twice yields the same final ACL).
///
/// - **Windows:** [`windows_harden_dir`] — squatter purge, owner→SYSTEM, `/reset`,
///   protected `{SYSTEM:F, Administrators:F, read_grant:R}` DACL, readback-verify.
/// - **Unix:** `create_dir_all` + `0700`; verified. (The interactive read grant on Unix is
///   the installer's best-effort `setfacl`, not applied here.)
pub fn harden_state_dir(dir: &Path, read_grant: Option<&str>) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        windows_harden_dir(dir, read_grant)
    }
    #[cfg(unix)]
    {
        let _ = read_grant;
        harden_unix_dir(dir)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = read_grant;
        std::fs::create_dir_all(dir)
    }
}

/// Unix harden: `0700`, owner-only, verified. Fail closed (remove the dir) if `0700` cannot
/// be established.
#[cfg(unix)]
fn harden_unix_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
    if mode != 0o700 {
        let _ = std::fs::remove_dir_all(dir);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "state dir {} is not 0700 after hardening (got {mode:o})",
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// The current process TOKEN's user SID (`whoami /user`), or `None` when it cannot be
/// resolved OR is a forbidden group/SYSTEM SID — so a SERVICE running as SYSTEM yields
/// `None` (no interactive grant) and a spoofed `%USERNAME%=Everyone` can never leak in
/// (the SID comes from the token, and a group SID is rejected).
#[cfg(windows)]
fn current_user_sid() -> Option<String> {
    let out = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sid = parse_whoami_csv_sid(&String::from_utf8_lossy(&out.stdout))?;
    if is_forbidden_grant_sid(&sid) {
        return None;
    }
    Some(sid)
}

/// The current owner SID of `path` (a dir OR a file) via `Get-Acl`, or `None` if it can't be
/// read. Used both for the dir-trust checks (harden / discover) and the control-token FILE
/// owner verification ([`token_file_is_trusted`]).
#[cfg(windows)]
fn path_owner_sid(path: &Path) -> Option<String> {
    let dir = path.to_string_lossy().replace('\'', "''");
    let ps = format!(
        "(Get-Acl -LiteralPath '{dir}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.starts_with("S-1-") {
        Some(s)
    } else {
        None
    }
}

/// Discover an installer-set interactive read grant on a TRUSTED (SYSTEM/Administrators-owned)
/// pre-existing dir, to PRESERVE it across a SYSTEM service harden. `None` for an absent dir,
/// an untrusted-owner dir (a squatter — its grants are not preserved; the dir is purged), or a
/// dir with no per-user grant.
#[cfg(windows)]
fn discover_existing_read_grant(dir: &Path) -> Option<String> {
    if !dir.is_dir() {
        return None;
    }
    let trusted = matches!(
        path_owner_sid(dir).as_deref(),
        Some(SID_SYSTEM) | Some(SID_ADMINISTRATORS)
    );
    if !trusted {
        return None;
    }
    let ps = acl_verify_ps_command(&dir.to_string_lossy());
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_first_user_read_sid(&String::from_utf8_lossy(&out.stdout))
}

/// Run `icacls` with `args`; `Ok(())` iff it exits 0, else an `Err` carrying the exit code +
/// stderr. No shell — args are passed directly.
#[cfg(windows)]
fn run_icacls(args: &[String]) -> std::io::Result<()> {
    let out = std::process::Command::new("icacls").args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "icacls exited with {}: {}",
            out.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string()),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Read `dir`'s ACL back and verify it meets the acceptance gate ([`parse_acl_verify`]).
#[cfg(windows)]
fn read_and_verify_acl(dir: &Path, read_grant: Option<&str>) -> std::io::Result<()> {
    let ps = acl_verify_ps_command(&dir.to_string_lossy());
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "Get-Acl readback exited non-zero: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    parse_acl_verify(&String::from_utf8_lossy(&out.stdout), read_grant)
        .map_err(std::io::Error::other)
}

/// Windows: the full #501 hardening contract, fail-closed (see the module docs). Purges a
/// squatter-owned pre-existing dir, forces owner = SYSTEM, drops all foreign ACEs, applies a
/// protected `{SYSTEM:F, Administrators:F[, read_grant:R]}` DACL, and READBACK-VERIFIES it.
/// On any failure the dir is best-effort deleted and an `Err` is returned.
#[cfg(windows)]
fn windows_harden_dir(dir: &Path, read_grant: Option<&str>) -> std::io::Result<()> {
    let path_str = dir.to_string_lossy().into_owned();

    // 1. Squatting defense: a pre-existing dir with an UNTRUSTED owner is purged (take
    //    ownership so it can be deleted, then remove). Fail closed if it can't be purged
    //    rather than adopt an attacker-controlled directory.
    if dir.exists() {
        let trusted = matches!(
            path_owner_sid(dir).as_deref(),
            Some(SID_SYSTEM) | Some(SID_ADMINISTRATORS)
        );
        if !trusted {
            let _ = run_icacls(&setowner_system_args(&path_str));
            std::fs::remove_dir_all(dir).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "state dir {path_str} pre-existed with an untrusted/unknown owner and could not be purged ({e}); refusing (fail closed)"
                    ),
                )
            })?;
        }
    }

    // 2. Create (idempotent if we just adopted a trusted pre-existing dir).
    std::fs::create_dir_all(dir)?;

    // 3-5. Owner→SYSTEM, purge foreign ACEs (/reset), then the protected DACL.
    let lockdown = run_icacls(&setowner_system_args(&path_str))
        .and_then(|_| run_icacls(&reset_dacl_args(&path_str)))
        .and_then(|_| run_icacls(&windows_lockdown_grant_args(&path_str, read_grant)));
    if let Err(e) = lockdown {
        let _ = std::fs::remove_dir_all(dir);
        return Err(std::io::Error::other(format!(
            "ACL lockdown FAILED ({e}); removed the state dir (fail closed)"
        )));
    }

    // 6. Readback-verify. Fail closed on any violation.
    if let Err(e) = read_and_verify_acl(dir, read_grant) {
        let _ = std::fs::remove_dir_all(dir);
        return Err(std::io::Error::other(format!(
            "ACL readback verification FAILED ({e}); removed the state dir (fail closed)"
        )));
    }
    Ok(())
}

/// A BEST-EFFORT inheritable grant for the fresh-create path ([`ensure_dir_restricted`]):
/// `icacls /inheritance:r /grant:r *SYSTEM:F *Administrators:F [*<user>:F]`. Not the
/// authoritative gate (no owner reset, no `/reset` purge, no readback) — that is
/// [`windows_harden_dir`] on the service run. Grants the creating REAL user (process-token
/// SID) FULL because THIS process must WRITE the token it is about to mint into the dir it
/// just created (the dev / self-create path); a READ-only grant would deny that write. FULL
/// is still a superset of read and still denies every OTHER local user (the security
/// property that matters); the authoritative service harden later re-locks the interactive
/// user to READ. Silent best-effort.
#[cfg(windows)]
fn windows_grant_best_effort(dir: &Path) {
    let mut args = vec![
        dir.to_string_lossy().into_owned(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        format!("*{SID_SYSTEM}:(OI)(CI)F"),
        "/grant:r".to_string(),
        format!("*{SID_ADMINISTRATORS}:(OI)(CI)F"),
    ];
    if let Some(sid) = current_user_sid() {
        args.push("/grant:r".to_string());
        args.push(format!("*{sid}:(OI)(CI)F"));
    }
    let _ = std::process::Command::new("icacls")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins_over_everything() {
        let chosen = choose_state_dir(
            Some(PathBuf::from("/custom/state")),
            &[PathBuf::from("/var/lib/dig-node")],
            &|_p| true, // machine exists…
            &|_p| true, // …and is creatable — override still wins.
            true,
            PathBuf::from("/home/u/.local/DigNode"),
        );
        assert_eq!(chosen, PathBuf::from("/custom/state"));
    }

    #[test]
    fn existing_machine_dir_is_used_by_anyone_even_a_non_service() {
        // The reported bug's fix: the CLI (is_service=false) MUST resolve the same
        // machine dir the service created, so it reads the same control token.
        let machine = PathBuf::from("/var/lib/dig-node");
        let chosen = choose_state_dir(
            None,
            std::slice::from_ref(&machine),
            &|p| p == machine, // it already exists
            &|_p| false,
            false, // NOT a service (the operator CLI)
            PathBuf::from("/home/u/.local/DigNode"),
        );
        assert_eq!(chosen, machine);
    }

    #[test]
    fn service_creates_first_creatable_machine_candidate_when_none_exist() {
        let primary = PathBuf::from("/var/lib/dig-node");
        let fallback = PathBuf::from("/etc/dig-node");
        let chosen = choose_state_dir(
            None,
            &[primary.clone(), fallback.clone()],
            &|_p| false,        // none exist yet
            &|p| p == fallback, // only /etc is creatable here
            true,               // a service run
            PathBuf::from("/home/u/.local/DigNode"),
        );
        assert_eq!(chosen, fallback, "picks the first creatable candidate");
    }

    #[test]
    fn non_service_falls_back_to_legacy_when_no_machine_dir_exists() {
        // A dev `dig-node run` as a normal user with no machine-wide dir keeps using the
        // legacy per-user dir (no ProgramData pollution, existing workflow preserved).
        let legacy = PathBuf::from("/home/u/.local/DigNode");
        let chosen = choose_state_dir(
            None,
            &[PathBuf::from("/var/lib/dig-node")],
            &|_p| false, // machine dir absent
            &|_p| true,  // even if creatable, a non-service must NOT create it
            false,       // dev run, not a service
            legacy.clone(),
        );
        assert_eq!(chosen, legacy);
    }

    #[test]
    fn service_falls_back_to_legacy_when_machine_dir_uncreatable() {
        // A user-level Linux/macOS service that cannot create /var/lib falls back to the
        // legacy per-user dir — which, since the service runs AS the installing user,
        // is the SAME dir that user's CLI resolves, so they still agree.
        let legacy = PathBuf::from("/home/u/.local/DigNode");
        let chosen = choose_state_dir(
            None,
            &[
                PathBuf::from("/var/lib/dig-node"),
                PathBuf::from("/etc/dig-node"),
            ],
            &|_p| false, // absent
            &|_p| false, // uncreatable (no privilege)
            true,        // a service run
            legacy.clone(),
        );
        assert_eq!(chosen, legacy);
    }

    #[test]
    fn machine_state_dirs_are_absolute_and_identity_independent() {
        // Whatever the OS, the machine candidates must be absolute and must NOT contain a
        // per-user segment (the whole point — they do not vary by the running user).
        for d in machine_state_dirs() {
            assert!(d.is_absolute(), "{d:?} must be absolute");
            let s = d.to_string_lossy().to_lowercase();
            assert!(
                !s.contains("appdata") && !s.contains("/users/") && !s.contains("systemprofile"),
                "{d:?} must be identity-independent"
            );
        }
    }

    #[test]
    fn is_machine_state_dir_matches_only_the_real_candidates() {
        for d in machine_state_dirs() {
            assert!(is_machine_state_dir(&d), "{d:?} is a machine candidate");
        }
        // A test temp dir / legacy per-user dir is NOT a machine dir (so it is never
        // hardened/purged — the DIG_NODE_STATE_DIR override + legacy fallback stay safe).
        assert!(!is_machine_state_dir(
            &std::env::temp_dir().join("dig-node-not-machine")
        ));
        assert!(!is_machine_state_dir(Path::new("/home/u/.local/DigNode")));
    }

    #[test]
    fn running_as_service_reads_the_run_context_env() {
        // PURE-ish: exercised via the env contract. Save/restore so we don't leak state.
        let prev = std::env::var(RUN_CONTEXT_ENV).ok();
        std::env::set_var(RUN_CONTEXT_ENV, "service");
        assert!(running_as_service());
        std::env::set_var(RUN_CONTEXT_ENV, "SERVICE");
        assert!(running_as_service(), "case-insensitive");
        std::env::set_var(RUN_CONTEXT_ENV, "cli");
        assert!(!running_as_service());
        std::env::remove_var(RUN_CONTEXT_ENV);
        assert!(!running_as_service(), "unset ⇒ not a service");
        match prev {
            Some(v) => std::env::set_var(RUN_CONTEXT_ENV, v),
            None => std::env::remove_var(RUN_CONTEXT_ENV),
        }
    }

    // -- SID resolution + spoof guard (#501: spoofable grant principal) ----------

    #[test]
    fn parse_whoami_csv_sid_reads_the_token_sid() {
        // `whoami /user /fo csv /nh` → "domain\user","SID".
        assert_eq!(
            parse_whoami_csv_sid("\"mypc\\alice\",\"S-1-5-21-111-222-333-1001\"\r\n").as_deref(),
            Some("S-1-5-21-111-222-333-1001")
        );
        assert_eq!(parse_whoami_csv_sid("no sid here").as_deref(), None);
        assert_eq!(parse_whoami_csv_sid("").as_deref(), None);
    }

    #[test]
    fn forbidden_grant_sids_are_rejected() {
        // The exact spoof: %USERNAME%=Everyone → Everyone SID must be refused, as must the
        // other broad groups and SYSTEM (never the interactive grantee).
        assert!(is_forbidden_grant_sid(SID_EVERYONE));
        assert!(is_forbidden_grant_sid(SID_AUTHENTICATED_USERS));
        assert!(is_forbidden_grant_sid(SID_ANONYMOUS));
        assert!(is_forbidden_grant_sid(SID_USERS));
        assert!(is_forbidden_grant_sid(SID_SYSTEM));
        // A real interactive-user SID is allowed.
        assert!(!is_forbidden_grant_sid("S-1-5-21-111-222-333-1001"));
    }

    #[test]
    fn dangerous_group_sids_cover_the_broad_principals() {
        assert!(is_dangerous_group_sid(SID_EVERYONE));
        assert!(is_dangerous_group_sid(SID_AUTHENTICATED_USERS));
        assert!(is_dangerous_group_sid(SID_ANONYMOUS));
        assert!(is_dangerous_group_sid(SID_USERS));
        assert!(!is_dangerous_group_sid(SID_SYSTEM));
        assert!(!is_dangerous_group_sid(SID_ADMINISTRATORS));
        assert!(!is_dangerous_group_sid("S-1-5-21-1-2-3-1001"));
    }

    // -- icacls lockdown argv (owner reset + foreign-ACE purge + SID grants) -----

    #[test]
    fn setowner_forces_system_by_sid_recursively() {
        let args = setowner_system_args(r"C:\ProgramData\DigNode");
        assert!(args.iter().any(|a| a == "/setowner"));
        assert!(
            args.iter().any(|a| a == "*S-1-5-18"),
            "owner must be SYSTEM by SID"
        );
        assert!(args.iter().any(|a| a == "/T"), "recurse to children");
    }

    #[test]
    fn reset_purges_explicit_aces() {
        let args = reset_dacl_args(r"C:\ProgramData\DigNode");
        assert!(args.iter().any(|a| a == "/reset"));
        assert!(args.iter().any(|a| a == "/T"));
    }

    #[test]
    fn lockdown_grants_system_admins_and_the_read_sid() {
        let args =
            windows_lockdown_grant_args(r"C:\ProgramData\DigNode", Some("S-1-5-21-9-9-9-1001"));
        assert!(args.contains(&"/inheritance:r".to_string()));
        // SYSTEM + Administrators FULL by SID (not the localized name "SYSTEM").
        assert!(args.iter().any(|a| a == "*S-1-5-18:(OI)(CI)F"));
        assert!(args.iter().any(|a| a == "*S-1-5-32-544:(OI)(CI)F"));
        // The interactive user gets READ only, by SID.
        assert!(args.iter().any(|a| a == "*S-1-5-21-9-9-9-1001:(OI)(CI)R"));
        // Never the localized "SYSTEM" name, never Everyone/Users.
        assert!(!args.iter().any(|a| a.starts_with("SYSTEM:")));
        assert!(!args
            .iter()
            .any(|a| a.contains("Everyone") || a.contains("Users:") || a.contains("S-1-1-0")));
    }

    #[test]
    fn lockdown_without_a_read_grant_is_system_and_admins_only() {
        // A SYSTEM service with no discoverable interactive grant → SYSTEM + Admins only.
        let args = windows_lockdown_grant_args(r"C:\ProgramData\DigNode", None);
        assert!(args.iter().any(|a| a == "*S-1-5-18:(OI)(CI)F"));
        assert!(args.iter().any(|a| a == "*S-1-5-32-544:(OI)(CI)F"));
        // No user read ACE, and definitely no broad-group grant.
        assert!(!args.iter().any(|a| a.ends_with(":(OI)(CI)R")));
        assert!(!args
            .iter()
            .any(|a| a.contains("S-1-1-0") || a.contains("S-1-5-32-545")));
    }

    // -- readback ACL verification (the acceptance gate) -------------------------

    fn ok_acl_with_read(user: &str) -> String {
        format!("OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;{user};False\n")
    }
    fn ok_acl_no_read() -> String {
        "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\n".to_string()
    }

    #[test]
    fn verify_accepts_a_correctly_locked_dacl_with_read_grant() {
        let user = "S-1-5-21-1-2-3-1001";
        assert!(parse_acl_verify(&ok_acl_with_read(user), Some(user)).is_ok());
    }

    #[test]
    fn verify_accepts_system_and_admins_only_when_no_read_grant_required() {
        // A SYSTEM service dir with no interactive grant is valid (operator elevates).
        assert!(parse_acl_verify(&ok_acl_no_read(), None).is_ok());
    }

    #[test]
    fn verify_rejects_a_world_readable_ace() {
        // The priv-esc: Everyone/Users in the DACL.
        let bad =
            "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;S-1-5-32-545;False\n";
        let e = parse_acl_verify(bad, None).unwrap_err();
        assert!(e.contains("world/group"), "got: {e}");
    }

    #[test]
    fn verify_rejects_an_inherited_ace() {
        // Inheritance not disabled → the dir can inherit ProgramData's Users ACE.
        let bad = "OWNER;S-1-5-18\nACE;S-1-5-18;True\nACE;S-1-5-32-544;False\nACE;S-1-5-21-1-2-3-1001;False\n";
        let e = parse_acl_verify(bad, Some("S-1-5-21-1-2-3-1001")).unwrap_err();
        assert!(e.contains("inheritance is NOT disabled"), "got: {e}");
    }

    #[test]
    fn verify_rejects_an_untrusted_owner() {
        // A squatter-owned dir (owner = a normal user) must fail: owner keeps WRITE_DAC.
        let bad = "OWNER;S-1-5-21-1-2-3-1001\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;S-1-5-21-1-2-3-1001;False\n";
        let e = parse_acl_verify(bad, Some("S-1-5-21-1-2-3-1001")).unwrap_err();
        assert!(e.contains("owner is"), "got: {e}");
    }

    #[test]
    fn verify_rejects_a_missing_system_ace() {
        let bad = "OWNER;S-1-5-18\nACE;S-1-5-32-544;False\n";
        let e = parse_acl_verify(bad, None).unwrap_err();
        assert!(e.contains("missing the required ACE"), "got: {e}");
    }

    #[test]
    fn verify_rejects_a_missing_required_read_grant() {
        // A read grant was applied but the readback lacks it → operator can't read the token.
        let e = parse_acl_verify(&ok_acl_no_read(), Some("S-1-5-21-1-2-3-1001")).unwrap_err();
        assert!(e.contains("missing the interactive read grant"), "got: {e}");
    }

    #[test]
    fn verify_rejects_an_unexpected_surviving_principal() {
        // A squatter user SID that survived the reset (or an unexpected extra trustee) must
        // be rejected even though it is not a well-known group. No read grant was applied, so
        // ANY per-user SID present is unexpected.
        let bad = "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;S-1-5-21-7-7-7-1002;False\n";
        let e = parse_acl_verify(bad, None).unwrap_err();
        assert!(e.contains("unexpected principal"), "got: {e}");
    }

    #[test]
    fn acl_verify_ps_command_targets_the_dir_and_emits_sids() {
        let cmd = acl_verify_ps_command(r"C:\ProgramData\DigNode");
        assert!(cmd.contains("Get-Acl"));
        assert!(cmd.contains(r"C:\ProgramData\DigNode"));
        assert!(cmd.contains("SecurityIdentifier"));
        assert!(cmd.contains("OWNER;"));
        assert!(cmd.contains("ACE;"));
    }

    // -- discover an installer-set interactive read grant to preserve ------------

    #[test]
    fn discover_finds_the_first_user_read_sid() {
        let acl = ok_acl_with_read("S-1-5-21-1-2-3-1001");
        assert_eq!(
            parse_first_user_read_sid(&acl).as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
    }

    #[test]
    fn discover_ignores_system_admins_and_groups() {
        // Only SYSTEM + Admins (+ a group, which should never be here) → nothing to preserve.
        let acl =
            "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;S-1-5-32-545;False\n";
        assert_eq!(parse_first_user_read_sid(acl), None);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dir_restricted_is_0700_and_not_group_or_world_accessible() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("dig-state-dir-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        ensure_dir_restricted(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "state dir must be owner-only (got {mode:o})");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- control-token FILE owner verification (#501 residual) ------------------

    #[cfg(windows)]
    #[test]
    fn windows_token_owner_trust_rules() {
        // SYSTEM + Administrators are trusted on BOTH a service and a non-service run.
        assert!(windows_token_owner_is_trusted(SID_SYSTEM, true, None));
        assert!(windows_token_owner_is_trusted(SID_SYSTEM, false, None));
        assert!(windows_token_owner_is_trusted(
            SID_ADMINISTRATORS,
            true,
            None
        ));
        let user = "S-1-5-21-1-2-3-1001";
        // A SERVICE run must NOT trust a token owned by a normal user (the priv-esc)…
        assert!(!windows_token_owner_is_trusted(user, true, Some(user)));
        // …but a NON-service run trusts the CURRENT user's own token.
        assert!(windows_token_owner_is_trusted(user, false, Some(user)));
        // A DIFFERENT user's token (a squatter) is never trusted on a non-service run.
        assert!(!windows_token_owner_is_trusted(
            user,
            false,
            Some("S-1-5-21-9-9-9-2002")
        ));
        // Indeterminate current user on a non-service run → lenient (no needless churn).
        assert!(windows_token_owner_is_trusted(user, false, None));
    }

    #[cfg(unix)]
    #[test]
    fn unix_token_owner_trust_rules() {
        let me = 1000u32;
        // root-owned is trusted regardless of mode (a root/elevated installer wrote it).
        assert!(unix_token_owner_is_trusted(0, 0o644, me));
        assert!(unix_token_owner_is_trusted(0, 0o600, me));
        // My own owner-only (0600) token is trusted.
        assert!(unix_token_owner_is_trusted(me, 0o600, me));
        // My own but group/other-readable token is NOT trusted.
        assert!(!unix_token_owner_is_trusted(me, 0o644, me));
        assert!(!unix_token_owner_is_trusted(me, 0o660, me));
        // Another user's token (a squatter) is NOT trusted even at 0600.
        assert!(!unix_token_owner_is_trusted(1001, 0o600, me));
    }

    #[cfg(windows)]
    #[test]
    fn token_file_is_trusted_rejects_a_service_run_on_a_user_owned_file() {
        // A file THIS (interactive-user) process creates is owned by the current user. A
        // NON-service run trusts it; a SERVICE run does NOT (it requires SYSTEM/Administrators).
        let dir = std::env::temp_dir().join(format!(
            "dig-token-owner-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control-token");
        std::fs::write(&path, b"deadbeef").unwrap();
        assert!(
            token_file_is_trusted(&path, false),
            "a non-service run trusts the current user's own token"
        );
        assert!(
            !token_file_is_trusted(&path, true),
            "a service run must NOT trust a user-owned token"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn token_file_is_trusted_accepts_0600_rejects_group_readable() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "dig-token-owner-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control-token");
        std::fs::write(&path, b"deadbeef").unwrap();
        // A 0600 file owned by the test user (== current euid) is trusted.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            token_file_is_trusted(&path, false),
            "own 0600 token is trusted"
        );
        // A group/other-readable (0644) file is NOT trusted — UNLESS we are root (uid 0), where
        // a root-owned file is legitimately trusted regardless of mode.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let running_as_root = std::fs::metadata(&path)
            .map(|m| m.uid() == 0)
            .unwrap_or(false);
        if !running_as_root {
            assert!(
                !token_file_is_trusted(&path, false),
                "a group/other-readable token is not trusted"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn harden_state_dir_sets_0700_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("dig-harden-dir-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        harden_state_dir(&dir, None).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "harden must leave the dir 0700 (got {mode:o})");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
