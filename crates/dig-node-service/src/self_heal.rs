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
///   `WRITE_DAC` and so is treated as user-writable). The owner SID is read directly through the
///   Win32 security API (spawning no process) and compared for EQUALITY against the well-known
///   SYSTEM/Administrators SIDs; any read failure fails CLOSED (untrusted).
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

/// Windows: read `dir`'s OWNER SID directly via the Win32 security API and accept only the
/// well-known LocalSystem or BUILTIN\Administrators owner. Fails CLOSED on any read error. The
/// acceptance policy is kept PURE in [`owner_sid_is_privileged`] so it is unit-testable without a
/// real ACL.
///
/// # Why the Win32 API and not a spawned owner probe (#565 LPE, second-order)
///
/// An earlier version shelled out to `powershell (Get-Acl …).Owner`. Windows resolves a BARE
/// program name against the *application directory* (this service's [`std::env::current_exe`]
/// parent — the very install root being classified) BEFORE the real `System32` PowerShell. So a
/// low-privilege user who can write that root — the EXACT condition this gate exists to REFUSE —
/// could plant a trojan `powershell.exe` there and have the SYSTEM service execute it before the
/// owner check even returned: the guard undoing its own "never a bare name" invariant. Reading the
/// owner SID through `GetNamedSecurityInfoW` launches no process at all, closing that hole.
#[cfg(windows)]
fn windows_owner_is_privileged(dir: &Path) -> bool {
    match read_owner_sid_string(dir) {
        Some(sid) => owner_sid_is_privileged(&sid),
        // Indeterminate (path missing, access denied, alloc failure) = untrusted.
        None => false,
    }
}

/// PURE: does an owner SID *string* (e.g. `S-1-5-18`) name a privileged owner? Compared for exact
/// EQUALITY against the well-known LocalSystem (`S-1-5-18`) and BUILTIN\Administrators
/// (`S-1-5-32-544`) SIDs — never a localized display name and never a `\Administrators` name
/// suffix, so a domain group merely *named* "Administrators" (a different SID) does NOT pass.
#[cfg(windows)]
fn owner_sid_is_privileged(sid: &str) -> bool {
    let sid = sid.trim().to_ascii_uppercase();
    sid == "S-1-5-18" || sid == "S-1-5-32-544"
}

/// Read `dir`'s owner SID as its canonical string form (`S-1-5-…`) via the Win32 security API,
/// launching NO process. Returns `None` on any failure (missing path, access denied, allocation
/// failure) so the caller can treat an indeterminate owner as untrusted (fail closed).
#[cfg(windows)]
fn read_owner_sid_string(dir: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;

    // Null-terminated UTF-16 path for the wide Win32 call.
    let wide: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut owner_sid = std::ptr::null_mut();
    let mut security_descriptor = std::ptr::null_mut();

    // SAFETY: `wide` is a valid null-terminated UTF-16 string live for the whole call; the owner
    // and descriptor out-params are null-initialized and written by the OS. On ERROR_SUCCESS the
    // returned `security_descriptor` owns `owner_sid`'s storage and MUST be released with
    // `LocalFree`; neither pointer is dereferenced after that free.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner_sid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if status != ERROR_SUCCESS || owner_sid.is_null() {
        if !security_descriptor.is_null() {
            // SAFETY: freeing the LocalAlloc'd descriptor the API returned; null is a no-op.
            unsafe { LocalFree(security_descriptor as _) };
        }
        return None;
    }

    // Convert the owner SID to its canonical string form. `ConvertSidToStringSidW` LocalAlloc's the
    // string; we copy it out and free it below.
    let mut sid_string_ptr: *mut u16 = std::ptr::null_mut();
    // SAFETY: `owner_sid` is a valid SID (non-null, from a successful GetNamedSecurityInfoW); the
    // out-pointer is null-initialized and, on success (non-zero), receives a LocalAlloc'd
    // null-terminated wide string freed below.
    let converted = unsafe { ConvertSidToStringSidW(owner_sid, &mut sid_string_ptr) };
    let result = if converted != 0 && !sid_string_ptr.is_null() {
        Some(wide_ptr_to_string(sid_string_ptr))
    } else {
        None
    };

    // SAFETY: both handles are the exact LocalAlloc'd blocks the two APIs returned; a null free is
    // a documented no-op and neither pointer is used again.
    unsafe {
        if !sid_string_ptr.is_null() {
            LocalFree(sid_string_ptr as _);
        }
        LocalFree(security_descriptor as _);
    }
    result
}

/// Copy a null-terminated wide (UTF-16) string from a raw pointer into an owned `String`.
#[cfg(windows)]
fn wide_ptr_to_string(ptr: *const u16) -> String {
    let mut len = 0usize;
    // SAFETY: `ptr` is a valid null-terminated UTF-16 string (from ConvertSidToStringSidW); we walk
    // to the terminator and read exactly that many code units.
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
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

    /// The owner-SID policy accepts ONLY the well-known SYSTEM / BUILTIN\Administrators SIDs, by
    /// exact SID EQUALITY. A localized/display NAME is not a SID and never passes, and — the #565
    /// second-order fix — a lookalike group literally *named* "Administrators" (any other SID) is
    /// rejected, closing the old `\administrators` name-suffix match a domain group could satisfy.
    #[cfg(windows)]
    #[test]
    fn windows_owner_policy_accepts_only_the_well_known_system_or_administrators_sids() {
        assert!(owner_sid_is_privileged("S-1-5-18"));
        assert!(owner_sid_is_privileged("S-1-5-32-544"));
        // Case/whitespace-insensitive on the canonical SID string.
        assert!(owner_sid_is_privileged("  s-1-5-18  "));

        // Display names are not SIDs — never accepted (the probe only ever feeds SID strings).
        assert!(!owner_sid_is_privileged("NT AUTHORITY\\SYSTEM"));
        assert!(!owner_sid_is_privileged("BUILTIN\\Administrators"));
        // A lookalike domain group named "Administrators" has a DIFFERENT SID — must be rejected
        // (the old name-suffix match wrongly accepted `\administrators`).
        assert!(!owner_sid_is_privileged(
            "S-1-5-21-1004336348-1177238915-682003330-512"
        ));
        assert!(!owner_sid_is_privileged("CONTOSO\\Administrators"));
        // Ordinary users / broad groups are rejected.
        assert!(!owner_sid_is_privileged("S-1-5-32-545")); // BUILTIN\Users
        assert!(!owner_sid_is_privileged("S-1-1-0")); // Everyone
        assert!(!owner_sid_is_privileged("MACHINE\\alice"));
    }

    /// Regression (#565 LPE, second-order): the owner probe must NEVER execute a binary planted in
    /// the very directory it is classifying. A low-privilege user owns a tempdir (the user-writable
    /// install root the gate must refuse) and plants a `powershell.exe` there; the SID-based probe
    /// must (a) read the tempdir's real owner (the non-privileged test user) and report NOT
    /// privileged, and (b) launch nothing — so the planted binary leaves no side effect. The
    /// old bare-name `Command::new("powershell")` resolved against the application directory,
    /// re-introducing exactly this LPE; the Win32-API probe spawns no process at all.
    #[cfg(windows)]
    #[test]
    fn windows_owner_probe_never_executes_a_planted_powershell_in_the_target_root() {
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("pwned.txt");
        // A "powershell.exe" that, IF executed, would create the sentinel. (A .cmd payload behind
        // an .exe name suffices to prove execution; the probe must not run it either way.)
        std::fs::write(
            dir.path().join("powershell.exe"),
            format!("@echo off\r\n> \"{}\" echo pwned\r\n", sentinel.display()),
        )
        .unwrap();

        // A freshly-created tempdir is owned by the (non-SYSTEM/Admin) test user.
        assert!(
            !windows_owner_is_privileged(dir.path()),
            "a user-owned install root must classify as NOT privileged"
        );
        assert_eq!(
            resolve_privileged_sibling_in(dir.path(), "dig-updater"),
            Err(ResolveError::UserWritableRoot),
            "the user-writable root must be refused (LPE #565)"
        );
        assert!(
            !sentinel.exists(),
            "the owner probe must launch NO process — the planted powershell.exe must never run"
        );
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
