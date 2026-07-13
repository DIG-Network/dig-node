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
//! # Security (the crux — see [`ensure_dir_restricted`] / [`restrict_file`])
//!
//! The control token grants FULL local control of the node (mint controller tokens,
//! change pins, drive wallet-adjacent control). A machine-wide file must therefore NOT be
//! world/all-users-readable, or ANY local user could seize control (a local privilege
//! escalation). The token dir + files are created with a restrictive ACL granting EXACTLY
//! SYSTEM + Administrators + the creating user, and NO ONE ELSE. On Unix the dir is `0700`
//! and the token file `0600`; on Windows inherited ACEs are stripped (`icacls
//! /inheritance:r`) and only those three trustees are granted (inheritable) — never the
//! default `ProgramData` grant that lets all Users read. The creating user is granted full
//! (it must write the token it mints, and an elevated installer must retain read); the
//! security-critical property is that every OTHER local user is denied.

use std::path::{Path, PathBuf};

/// The env var that overrides the resolved state dir outright (tests + custom deploys).
pub const STATE_DIR_ENV: &str = "DIG_NODE_STATE_DIR";

/// The env var the INSTALLED service carries so it self-identifies as a service run
/// (set by `dig-node install` into the service environment, and by the Windows SCM
/// entrypoint at runtime). Only a service run may CREATE the machine-wide dir when it is
/// absent; the CLI never does (it only reads an existing one, else the legacy dir).
pub const RUN_CONTEXT_ENV: &str = "DIG_NODE_RUN_CONTEXT";

/// The value of [`RUN_CONTEXT_ENV`] that marks a service run.
pub const RUN_CONTEXT_SERVICE: &str = "service";

/// The machine-wide base folder name (Windows/macOS) — `DigNode` under `%PROGRAMDATA%` /
/// `/Library/Application Support`. Linux uses the kebab `dig-node` path directly.
const MACHINE_FOLDER: &str = "DigNode";

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

/// Whether THIS process is the installed service (so it may create the machine-wide dir
/// when absent). Driven by [`RUN_CONTEXT_ENV`] — set by `dig-node install` into the
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
/// real filesystem/env into [`choose_state_dir`]. A chosen MACHINE (or override) dir is
/// created with a restrictive ACL as a side effect of resolution when this is a service
/// run bootstrapping it; a chosen legacy dir is left to the token writer (its per-user
/// location is already user-scoped, matching the pre-#501 behaviour).
pub fn state_dir() -> PathBuf {
    let override_dir = std::env::var(STATE_DIR_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let candidates = machine_state_dirs();
    let is_service = running_as_service();
    let exists = |p: &Path| p.is_dir();
    // "Can create" = we successfully created it with a restrictive ACL (idempotent).
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

/// Ensure `dir` exists with a RESTRICTIVE ACL so it is not world/all-users-readable — the
/// crux of the #501 security model. The tightening is applied ONLY when THIS call creates the
/// dir fresh; an already-existing dir is left untouched so a later service run (as SYSTEM /
/// root) does NOT clobber the ACL the INSTALLER carefully set (which grants the interactive
/// install-user read — [`crate::service::install`]). On a fresh create: Unix `0700`; Windows
/// inheritance-removed with only SYSTEM + Administrators (+ the creating user) granted, made
/// inheritable so files created inside inherit the same tight ACL.
///
/// Whoever creates the dir FIRST fixes its ACL: an elevated `dig-node install` (running as the
/// interactive user) grants that user read; a bare service bootstrap (running as SYSTEM/root)
/// grants only the daemon identity, so a non-elevated operator CLI cannot read the token and
/// gets the precise elevation/ACL remedy ([`crate::control::control_token_remedy`]).
///
/// Best-effort on the ACL step (a failure to tighten must not hard-fail node startup — the
/// loopback bind + token possession are the primary gate), but the `create_dir_all` itself is
/// surfaced so a caller can fall back to another candidate.
pub fn ensure_dir_restricted(dir: &Path) -> std::io::Result<()> {
    // Already present ⇒ trust its ACL (the installer, or a prior run, established it). Do NOT
    // re-tighten: a SYSTEM/root service re-applying the ACL would drop the interactive user's
    // explicit read grant, re-breaking #501 for the operator CLI.
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
        windows_restrict_dir(dir);
    }
    Ok(())
}

/// Restrict a control/auth FILE (the control token, the paired-token store) so it is NOT
/// readable by every local user.
///
/// - **Unix:** set the file to `0600` (owner read/write only) — the CI-gated assertion path.
/// - **Windows:** a NO-OP by design. The file INHERITS the tight, inheritable ACL of its
///   parent state dir ([`ensure_dir_restricted`]), which is where the security boundary lives.
///   Re-applying an explicit `icacls /inheritance:r` here would be actively harmful: when the
///   daemon runs as SYSTEM it would grant only SYSTEM/Administrators and STRIP the interactive
///   install-user's inherited read ACE, re-breaking #501 for the operator CLI. A freshly-created
///   file under the restricted dir is already non-world-readable via inheritance.
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

/// The current user's `DOMAIN\User` account name from the environment, for the Windows
/// ACL grant (so the interactive user / dev who created the token can still read it).
/// `None` when the environment does not carry it (then only SYSTEM + Administrators are
/// granted, and the CLI must be run elevated to read the token — surfaced in the remedy
/// hint).
#[cfg(windows)]
fn current_user_account() -> Option<String> {
    let user = std::env::var("USERNAME").ok()?;
    let user = user.trim();
    if user.is_empty() {
        return None;
    }
    match std::env::var("USERDOMAIN")
        .ok()
        .map(|d| d.trim().to_string())
    {
        Some(domain) if !domain.is_empty() => Some(format!("{domain}\\{user}")),
        _ => Some(user.to_string()),
    }
}

/// Apply a restrictive Windows ACL to the state DIR `path` via `icacls` (no shell — args are
/// passed directly). Removes inherited ACEs (`/inheritance:r`) so the world-readable
/// `%PROGRAMDATA%` default does NOT apply, then grants inheritable full (`(OI)(CI)(F)`) to
/// EXACTLY three trustees and NO ONE ELSE: SYSTEM (`*S-1-5-18`), Administrators
/// (`*S-1-5-32-544`), and the creating user.
///
/// The creating user gets FULL (not merely read): the SAME process that creates the dir must be
/// able to WRITE the token file into it (the dev/self-create path), and when an elevated
/// `dig-node install` creates the dir the interactive user must retain read afterwards — FULL is
/// a superset of read and, critically, still denies every OTHER local user, which is the
/// security property that matters (no local privilege escalation). When the daemon bootstraps the
/// dir as SYSTEM/root, the interactive user is simply not among the three trustees, so a
/// non-elevated operator CLI cannot read the token and gets the precise remedy. Inheritable, so
/// the token file created inside inherits exactly this tight ACL. Best-effort: a failure (icacls
/// missing/blocked) is ignored — the loopback bind + token possession remain the primary gate,
/// and Unix `0700`/`0600` is the CI-gated assertion path.
#[cfg(windows)]
fn windows_restrict_dir(path: &Path) {
    const GRANT: &str = "(OI)(CI)(F)";
    let mut cmd = std::process::Command::new("icacls");
    cmd.arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("*S-1-5-18:{GRANT}"))
        .arg(format!("*S-1-5-32-544:{GRANT}"));
    if let Some(user) = current_user_account() {
        cmd.arg(format!("{user}:{GRANT}"));
    }
    let _ = cmd
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
            &[machine.clone()],
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
}
