//! The always-on **self-heal driver** (#584 beacon re-arm + #651 ext-forcelist reconcile).
//!
//! The service runs this on startup and then on a fixed [`SELF_HEAL_TICK`] cadence, so a machine
//! whose auto-update beacon schedule or extension force-install policy has silently drifted gets
//! repaired without a manual elevated reinstall.
//!
//! # Two best-effort repairs, one privileged tick
//!
//! - **Beacon re-arm (#584).** Kicks `dig-updater schedule ensure`, the idempotent verb dig-updater
//!   ships (v0.13.0) that re-registers a provably-ABSENT daily schedule. This closes the
//!   chicken-and-egg where an already-dead schedule can never resurrect itself because nothing ever
//!   runs the beacon. `schedule ensure` respects a DELIBERATE opt-out itself (dig-updater
//!   `optout.rs`: `schedule uninstall` writes an Admin-only sentinel and `ensure` short-circuits to
//!   `SuppressedByOptOut`), so kicking it never re-arms a user's intentional uninstall — this driver
//!   does not need its own sentinel check, it simply defers to the verb's built-in guard.
//! - **Ext-forcelist reconcile (#651).** Reads the persisted update channel (`dig-updater channel
//!   get`) and re-applies it to every detected browser's force-install policy (`dig-installer
//!   --set-ext-forcelist-channel <channel>`, idempotent). This recovers the post-remove-failure
//!   uninstall gap in #613's staged channel switch (a crash after REMOVE but before RE-ADD leaves
//!   the extension uninstalled with the new channel already persisted, so an operator's
//!   `channel set` no-ops with `Unchanged` and never retries).
//!
//! # Security — absolute, privileged-root binary resolution only (#565 LPE)
//!
//! This service runs privileged (Windows LocalSystem / a root daemon), so a binary it spawns runs
//! with that privilege. A user-writable install root is therefore a local-privilege-escalation
//! vector: a low-privilege user who can drop a trojan `dig-updater`/`dig-installer` into a directory
//! the service spawns from would have it run as SYSTEM/root. [`resolve_privileged_sibling`] defends
//! this by resolving a sibling CLI ONLY by an ABSOLUTE path beside this running binary (the
//! admin-only #565 install root), and REJECTING that root outright when it is user-writable —
//! never a bare name resolved through `$PATH`, never a user-controllable candidate.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

/// The self-heal cadence: re-arm + reconcile once on startup, then every 6 hours (#584). Frequent
/// enough that a drift is repaired the same day, cheap enough that the two idempotent no-op passes
/// (a healthy machine's common case) cost nothing worth measuring.
pub const SELF_HEAL_TICK: Duration = Duration::from_secs(6 * 60 * 60);

/// Why [`resolve_privileged_sibling`] declined to hand back a spawnable path — each kept distinct so
/// a log line (and a test) can tell an ordinary "beacon not installed" apart from the security-
/// critical "the install root is user-writable, refusing to spawn from it".
#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// `current_exe()` (hence its parent install root) could not be determined.
    NoInstallRoot,
    /// The install root exists but is writable by a non-privileged user — spawning from it would be
    /// an LPE vector (#565), so it is refused rather than trusted.
    UserWritableRoot,
    /// The install root is trusted, but no such sibling binary is present on disk (the sibling tool
    /// is simply not installed) — the caller reports this as a benign no-op.
    NotFound,
}

/// The file name of a sibling CLI on this OS (`dig-updater` → `dig-updater.exe` on Windows).
fn sibling_file_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

/// Whether `dir` is a privileged directory safe to spawn a binary from — i.e. NOT writable by an
/// ordinary user. This is the LPE gate (#565): a SYSTEM/root service must never run a binary out of
/// a directory a low-privilege user could have planted one in.
///
/// - **Unix:** the directory must be owned by `root` (uid 0) AND carry no group/other write bit
///   (`mode & 0o022 == 0`). Either a non-root owner or a group/world-writable bit fails it.
/// - **Windows:** the directory's OWNER must be `SYSTEM` or `Administrators` (a user-owned dir keeps
///   `WRITE_DAC` and so is treated as user-writable). Read back via a PowerShell owner query; any
///   read/parse failure fails CLOSED (untrusted).
fn dir_is_privileged(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(dir) {
            Ok(md) => md.uid() == 0 && (md.mode() & 0o022) == 0,
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        windows_owner_is_privileged(dir)
    }
}

/// Windows: read `dir`'s owner and accept only SYSTEM / Administrators. Fails CLOSED on any
/// spawn/parse error. The acceptance policy is kept PURE in [`owner_is_privileged_sid`] so it is
/// unit-testable without a real ACL.
#[cfg(windows)]
fn windows_owner_is_privileged(dir: &Path) -> bool {
    let Some(dir_str) = dir.to_str() else {
        return false;
    };
    let command = format!(
        "$ErrorActionPreference='Stop'; (Get-Acl -LiteralPath '{}').Owner",
        dir_str.replace('\'', "''")
    );
    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .output()
    {
        Ok(out) if out.status.success() => {
            owner_is_privileged_sid(&String::from_utf8_lossy(&out.stdout))
        }
        _ => false,
    }
}

/// PURE: does an owner line (a name like `NT AUTHORITY\SYSTEM` / `BUILTIN\Administrators`, or the
/// well-known SID) name a privileged owner? Case-insensitive; trims surrounding whitespace.
#[cfg(windows)]
fn owner_is_privileged_sid(owner: &str) -> bool {
    let owner = owner.trim().to_ascii_lowercase();
    owner.ends_with("\\system")
        || owner == "s-1-5-18"
        || owner.ends_with("\\administrators")
        || owner == "s-1-5-32-544"
}

/// Resolve a sibling privileged CLI (`dig-updater` / `dig-installer`) to an ABSOLUTE, spawnable path
/// beside this running service binary — the admin-only #565 install root. Refuses a user-writable
/// root ([`ResolveError::UserWritableRoot`]) so a SYSTEM/root spawn can never run an attacker-
/// planted binary. Never consults `$PATH` and never accepts a bare name.
pub fn resolve_privileged_sibling(stem: &str) -> Result<PathBuf, ResolveError> {
    let exe = std::env::current_exe().map_err(|_| ResolveError::NoInstallRoot)?;
    let root = exe.parent().ok_or(ResolveError::NoInstallRoot)?;
    resolve_privileged_sibling_in(root, stem)
}

/// The [`resolve_privileged_sibling`] core with the install root supplied explicitly, so the LPE
/// gate + the absolute-path join can be exercised against a controlled directory in a test.
fn resolve_privileged_sibling_in(root: &Path, stem: &str) -> Result<PathBuf, ResolveError> {
    if !dir_is_privileged(root) {
        return Err(ResolveError::UserWritableRoot);
    }
    let candidate = root.join(sibling_file_name(stem));
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(ResolveError::NotFound)
    }
}

/// The arguments for the beacon re-arm kick — `dig-updater schedule ensure` (#584). PURE.
fn rearm_args() -> [&'static str; 2] {
    ["schedule", "ensure"]
}

/// The arguments that re-apply the force-install policy for `channel` — `dig-installer
/// --set-ext-forcelist-channel <channel>` (#651). PURE.
fn forcelist_reconcile_args(channel: &str) -> [&str; 2] {
    ["--set-ext-forcelist-channel", channel]
}

/// PURE: extract the channel token from a `dig-updater channel get --json` payload
/// (`{"command":"channel","channel":"stable"}`). `None` when the shape is unexpected.
fn parse_channel(json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()?
        .get("channel")?
        .as_str()
        .map(str::to_string)
}

/// What a single self-heal kick did — enough for a structured log line, best-effort throughout (a
/// failure NEVER propagates: the driver logs and moves on).
#[derive(Debug, PartialEq, Eq)]
pub enum KickOutcome {
    /// The binary was spawned; carries its exit success.
    Ran { ok: bool },
    /// The sibling tool is not installed — a benign no-op.
    NotInstalled,
    /// The install root was refused as user-writable (#565) — a security-relevant skip, logged loud.
    RefusedUserWritableRoot,
    /// The binary resolved but the OS failed to spawn it.
    SpawnFailed(String),
}

/// The injectable core of a kick: given an already-resolved binary path and args, spawn it (with
/// `--json` appended, matching every other dig-updater CLI call) and classify the result. Taking
/// `resolved` + `spawn` as parameters lets a test assert the resolved path is ABSOLUTE and the argv
/// is exactly what was intended, without a real privileged binary on disk.
async fn kick_with<Fut>(
    resolved: Result<PathBuf, ResolveError>,
    args: &[&str],
    spawn: impl FnOnce(PathBuf, Vec<String>) -> Fut,
) -> KickOutcome
where
    Fut: Future<Output = std::io::Result<Output>>,
{
    let bin = match resolved {
        Ok(bin) => bin,
        Err(ResolveError::NotFound | ResolveError::NoInstallRoot) => {
            return KickOutcome::NotInstalled
        }
        Err(ResolveError::UserWritableRoot) => return KickOutcome::RefusedUserWritableRoot,
    };
    let mut full: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    full.push("--json".to_string());
    match spawn(bin, full).await {
        Ok(out) => KickOutcome::Ran {
            ok: out.status.success(),
        },
        Err(e) => KickOutcome::SpawnFailed(e.to_string()),
    }
}

/// Spawn `bin` with `args` as a child process and collect its output. The production [`kick_with`]
/// spawner.
async fn spawn_process(bin: PathBuf, args: Vec<String>) -> std::io::Result<Output> {
    tokio::process::Command::new(&bin)
        .args(&args)
        .output()
        .await
}

/// Re-arm the beacon schedule (#584): kick `dig-updater schedule ensure` from the privileged install
/// root. Idempotent + opt-out-respecting (the verb itself honours the Admin-only opt-out sentinel).
pub async fn rearm_beacon_schedule() -> KickOutcome {
    kick_with(
        resolve_privileged_sibling("dig-updater"),
        &rearm_args(),
        spawn_process,
    )
    .await
}

/// Reconcile the ext-forcelist channel-follow state (#651): read the persisted channel from
/// `dig-updater channel get` and re-apply it to every browser via `dig-installer
/// --set-ext-forcelist-channel`. Best-effort: a missing dig-updater/dig-installer, or a channel we
/// cannot read, is a benign skip.
pub async fn reconcile_ext_forcelist() -> KickOutcome {
    let updater = match resolve_privileged_sibling("dig-updater") {
        Ok(bin) => bin,
        Err(ResolveError::UserWritableRoot) => return KickOutcome::RefusedUserWritableRoot,
        Err(_) => return KickOutcome::NotInstalled,
    };
    let channel = match spawn_process(
        updater,
        vec![
            "channel".to_string(),
            "get".to_string(),
            "--json".to_string(),
        ],
    )
    .await
    {
        Ok(out) if out.status.success() => parse_channel(&String::from_utf8_lossy(&out.stdout)),
        _ => None,
    };
    let Some(channel) = channel else {
        return KickOutcome::NotInstalled;
    };
    kick_with(
        resolve_privileged_sibling("dig-installer"),
        &forcelist_reconcile_args(&channel),
        spawn_process,
    )
    .await
}

/// Run one self-heal pass: re-arm the beacon schedule, then reconcile the ext-forcelist. Both are
/// best-effort and independent — one failing never blocks the other.
pub async fn run_once() {
    let rearm = rearm_beacon_schedule().await;
    eprintln!("dig-node: self-heal beacon re-arm: {rearm:?}");
    let reconcile = reconcile_ext_forcelist().await;
    eprintln!("dig-node: self-heal ext-forcelist reconcile: {reconcile:?}");
}

/// Spawn the always-on self-heal driver as a detached task: one pass immediately, then a pass every
/// [`SELF_HEAL_TICK`]. Detached + best-effort — it never blocks or fails the serve path. On an
/// unprivileged (dev/CLI) run its spawns simply resolve nothing and no-op.
pub fn spawn_driver() {
    tokio::spawn(async {
        let mut ticker = tokio::time::interval(SELF_HEAL_TICK);
        loop {
            ticker.tick().await;
            run_once().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Output};

    /// A canned successful [`Output`] so a spawn stub can hand back a real process result without
    /// launching anything. Only its status is read by [`kick_with`].
    fn ok_output() -> Output {
        #[cfg(unix)]
        let out = Command::new("true").output().unwrap();
        #[cfg(windows)]
        let out = Command::new("cmd").args(["/c", "exit 0"]).output().unwrap();
        out
    }

    #[test]
    fn sibling_file_name_is_os_correct() {
        if cfg!(windows) {
            assert_eq!(sibling_file_name("dig-updater"), "dig-updater.exe");
        } else {
            assert_eq!(sibling_file_name("dig-updater"), "dig-updater");
        }
    }

    #[test]
    fn rearm_kicks_schedule_ensure() {
        assert_eq!(rearm_args(), ["schedule", "ensure"]);
    }

    #[test]
    fn forcelist_reconcile_targets_the_given_channel() {
        assert_eq!(
            forcelist_reconcile_args("nightly"),
            ["--set-ext-forcelist-channel", "nightly"]
        );
    }

    #[test]
    fn parse_channel_reads_the_updater_json_shape() {
        assert_eq!(
            parse_channel(r#"{"command":"channel","channel":"stable"}"#).as_deref(),
            Some("stable")
        );
        assert_eq!(parse_channel(r#"{"command":"channel"}"#), None);
        assert_eq!(parse_channel("not json"), None);
    }

    // -- the LPE gate (#565): reject a user-writable install root --------------------------------

    #[test]
    fn resolve_rejects_a_user_writable_install_root() {
        // A freshly-created tempdir is owned by the (non-root) test user — exactly the user-writable
        // root the gate must refuse, on Unix (non-root owner) and Windows (user, not SYSTEM/Admin).
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_privileged_sibling_in(dir.path(), "dig-updater"),
            Err(ResolveError::UserWritableRoot),
            "a user-owned/user-writable install root must be refused (LPE #565)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_a_world_writable_root_even_with_a_present_binary() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // Plant a "binary" and make the dir world-writable — still refused (the world-writable bit).
        std::fs::write(dir.path().join("dig-updater"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            resolve_privileged_sibling_in(dir.path(), "dig-updater"),
            Err(ResolveError::UserWritableRoot)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_owner_policy_accepts_only_system_or_administrators() {
        assert!(owner_is_privileged_sid("NT AUTHORITY\\SYSTEM"));
        assert!(owner_is_privileged_sid("BUILTIN\\Administrators"));
        assert!(owner_is_privileged_sid("S-1-5-18"));
        assert!(owner_is_privileged_sid("S-1-5-32-544"));
        assert!(!owner_is_privileged_sid("MACHINE\\alice"));
        assert!(!owner_is_privileged_sid("BUILTIN\\Users"));
    }

    // -- the kick core: absolute path + exact argv, best-effort classification -------------------

    #[tokio::test]
    async fn kick_spawns_the_resolved_absolute_binary_with_json_appended() {
        use std::cell::RefCell;
        let seen: RefCell<Option<(PathBuf, Vec<String>)>> = RefCell::new(None);
        let bin = if cfg!(windows) {
            PathBuf::from(r"C:\Program Files\DIG\dig-updater.exe")
        } else {
            PathBuf::from("/opt/dig/bin/dig-updater")
        };
        let outcome = kick_with(Ok(bin.clone()), &rearm_args(), |b, a| {
            *seen.borrow_mut() = Some((b, a));
            async { Ok(ok_output()) }
        })
        .await;

        assert_eq!(outcome, KickOutcome::Ran { ok: true });
        let (spawned, args) = seen.into_inner().unwrap();
        assert!(
            spawned.is_absolute(),
            "the spawned binary path must be absolute"
        );
        assert_eq!(spawned, bin);
        assert_eq!(args, vec!["schedule", "ensure", "--json"]);
    }

    #[tokio::test]
    async fn kick_refuses_to_spawn_when_the_root_is_user_writable() {
        use std::cell::Cell;
        let spawned = Cell::new(false);
        let outcome = kick_with(
            Err(ResolveError::UserWritableRoot),
            &rearm_args(),
            |_b, _a| {
                spawned.set(true);
                async { Ok(ok_output()) }
            },
        )
        .await;
        assert_eq!(outcome, KickOutcome::RefusedUserWritableRoot);
        assert!(
            !spawned.get(),
            "a user-writable root must NEVER be spawned from"
        );
    }

    #[tokio::test]
    async fn kick_reports_not_installed_when_the_sibling_is_absent() {
        let outcome = kick_with(Err(ResolveError::NotFound), &rearm_args(), |_b, _a| async {
            Ok(ok_output())
        })
        .await;
        assert_eq!(outcome, KickOutcome::NotInstalled);
    }
}
