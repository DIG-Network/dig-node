//! Shared OS-owner trust gate: is a directory owned by a privileged principal, and therefore
//! NOT writable by an ordinary user?
//!
//! A SYSTEM/root service must never trust a directory a low-privilege user could tamper with —
//! whether it is a directory it *spawns a binary from* (the #565 LPE gate in [`crate::self_heal`])
//! or a directory it *reads a private key from* (the #661 TLS-root gate in [`crate::tls`], where a
//! user-writable root could hold an attacker-swapped `ca.key`). Both needs are the same question —
//! "is this directory privileged-owned?" — so the answer lives here ONCE ([`dir_is_privileged`]) and
//! both callers defer to it (DRY).
//!
//! The check fails CLOSED: any inability to determine the owner is treated as untrusted.
//!
//! The WHOLE path must be trustworthy, not just the leaf (#712): a privileged-owned leaf sitting
//! under a user-writable — or symlinked/junctioned — ANCESTOR can still be swapped out from beneath
//! (rename/replace of an intermediate directory is governed by the PARENT's permissions, and a
//! reparse point anywhere in the chain redirects the whole path). So [`dir_is_privileged`] walks
//! EVERY existing ancestor component and holds each to the same bar, and rejects any component that
//! is a symlink/junction/reparse point — matching the higher bar dig-dns already ships (#701).
//!
//! - **Unix:** every path component must be owned by `root` (uid 0), carry no group/other write bit
//!   (`mode & 0o022 == 0`), and NOT be a symlink (judged by `symlink_metadata`/lstat, so a symlink
//!   is classified on its own identity, never its target).
//! - **Windows:** every path component's OWNER SID must be the well-known LocalSystem (`S-1-5-18`),
//!   BUILTIN\Administrators (`S-1-5-32-544`), or `NT SERVICE\TrustedInstaller` (the fixed service
//!   SID that owns `C:\Program Files` and its protected subtree) — a user-owned dir keeps
//!   `WRITE_DAC` and so is treated as user-writable — AND the component must NOT be a reparse point
//!   (`FILE_ATTRIBUTE_REPARSE_POINT`). The owner SID is read directly through the Win32 security API
//!   — launching NO process — and compared for EQUALITY against those well-known SIDs.

use std::path::Path;

/// Whether `dir` is a privileged directory — owned by a privileged principal and safe from tampering
/// by an ordinary user AT EVERY LEVEL. The single trust gate shared by the self-heal spawn root
/// (#565), the TLS material root (#661), and the system-service install target (#46).
///
/// Walks the ENTIRE ancestor chain of `dir` (`dir`, its parent, … up to the filesystem root): every
/// component must be privileged-owned, not group/world-writable, and not a symlink/junction/reparse
/// point ([`component_is_privileged`]). A single weak component anywhere defeats the leaf's own
/// ownership, so one failure fails the whole check. Fails CLOSED: an indeterminate or missing
/// component is untrusted. `dir.ancestors()` always yields at least `dir`, so an empty chain can
/// never vacuously pass.
pub fn dir_is_privileged(dir: &Path) -> bool {
    dir.ancestors().all(component_is_privileged)
}

/// Whether a SINGLE existing path `component` clears the trust bar: privileged-owned, not
/// user-writable, and not a symlink/junction/reparse point. Fails CLOSED on any metadata error
/// (missing, access denied) — an indeterminate component is untrusted. Used for every level by
/// [`dir_is_privileged`].
#[cfg(unix)]
fn component_is_privileged(component: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // `symlink_metadata` (lstat) does NOT follow a symlink — a symlink component is judged on its
    // own identity so it can be rejected outright, never on the (possibly attacker-chosen) target.
    match std::fs::symlink_metadata(component) {
        Ok(md) => component_privileged(md.uid(), md.mode(), md.file_type().is_symlink()),
        Err(_) => false,
    }
}

/// PURE unix per-component policy: a component is privileged iff it is NOT a symlink, is owned by
/// root (uid 0), and grants no group/other write bit (`mode & 0o022 == 0`). Kept pure so every arm
/// is unit-tested without a real root-owned tree.
#[cfg(unix)]
fn component_privileged(uid: u32, mode: u32, is_symlink: bool) -> bool {
    !is_symlink && uid == 0 && (mode & 0o022) == 0
}

/// Whether a SINGLE existing path `component` clears the trust bar on Windows: not a reparse point,
/// and owned by a privileged principal. Fails CLOSED on any metadata/owner-read error. Used for
/// every level by [`dir_is_privileged`].
#[cfg(windows)]
fn component_is_privileged(component: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    // Reject a reparse point (symlink/junction/mount point) BEFORE trusting the owner: a reparse
    // anywhere in the chain redirects the whole path, and the owner read below would FOLLOW it.
    // `symlink_metadata` (a no-follow lstat) classifies the component on its own identity.
    match std::fs::symlink_metadata(component) {
        Ok(md) if attrs_are_reparse(md.file_attributes()) => false,
        Ok(_) => windows_owner_is_privileged(component),
        Err(_) => false,
    }
}

/// PURE: do NTFS file attributes carry the reparse-point flag (`FILE_ATTRIBUTE_REPARSE_POINT`) —
/// i.e. is this component a symlink, junction, or mount point? Kept pure so the bit test is
/// unit-tested without a real reparse point (which requires privilege to create).
#[cfg(windows)]
fn attrs_are_reparse(attrs: u32) -> bool {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0
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
pub(crate) fn windows_owner_is_privileged(dir: &Path) -> bool {
    match read_owner_sid_string(dir) {
        Some(sid) => owner_sid_is_privileged(&sid),
        // Indeterminate (path missing, access denied, alloc failure) = untrusted.
        None => false,
    }
}

/// The fixed `NT SERVICE\TrustedInstaller` service SID. It owns `C:\Program Files` and its protected
/// subtree by default, so the #712 ancestor walk MUST accept it or it would false-reject the
/// canonical `%ProgramFiles%\DIG\bin` install root (whose `C:\Program Files` ancestor is
/// TrustedInstaller-owned). It is a well-known constant — a service SID is derived deterministically
/// from the service name, so it is byte-identical on every Windows host — and is privileged: an
/// ordinary user cannot write a TrustedInstaller-owned directory without first taking ownership,
/// which itself requires privilege.
#[cfg(windows)]
const SID_TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// PURE: does an owner SID *string* (e.g. `S-1-5-18`) name a privileged owner? Compared for exact
/// EQUALITY against the well-known LocalSystem (`S-1-5-18`), BUILTIN\Administrators (`S-1-5-32-544`),
/// and `NT SERVICE\TrustedInstaller` ([`SID_TRUSTED_INSTALLER`]) SIDs — never a localized display
/// name and never a `\Administrators` name suffix, so a domain group merely *named* "Administrators"
/// (a different SID) does NOT pass.
#[cfg(windows)]
pub(crate) fn owner_sid_is_privileged(sid: &str) -> bool {
    let sid = sid.trim().to_ascii_uppercase();
    sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == SID_TRUSTED_INSTALLER
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

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;

    /// A freshly-created tempdir is owned by the (non-privileged) test user — exactly the
    /// user-writable directory the gate must refuse, on Unix (non-root owner) and Windows (a user,
    /// not SYSTEM/Administrators, owner).
    #[test]
    fn a_user_owned_dir_is_not_privileged() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            !super::dir_is_privileged(dir.path()),
            "a user-owned directory must not be trusted as privileged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_world_writable_dir_is_not_privileged() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            !dir_is_privileged(dir.path()),
            "a world-writable directory must not be trusted even if root-owned"
        );
    }

    /// The PURE unix per-component policy (#712): a component passes ONLY when it is root-owned, not
    /// group/world-writable, AND not a symlink. This is the per-level bar the ancestor walk applies.
    #[cfg(unix)]
    #[test]
    fn unix_component_policy_requires_root_owned_non_writable_non_symlink() {
        // Root-owned, non-symlink, root-only-writable — the only shape that passes.
        assert!(component_privileged(0, 0o755, false));
        assert!(component_privileged(0, 0o700, false));
        assert!(component_privileged(0, 0o555, false));

        // A symlink is rejected even when root-owned + not writable (#712 reparse rejection): a
        // symlinked component could redirect the privileged path onto an attacker-chosen target.
        assert!(!component_privileged(0, 0o755, true));

        // Ownership / writability failures.
        assert!(!component_privileged(1000, 0o755, false)); // not root-owned
        assert!(!component_privileged(0, 0o775, false)); // group-writable
        assert!(!component_privileged(0, 0o757, false)); // world-writable
    }

    /// Regression (#712): a symlink ANYWHERE in the chain is refused — here the leaf itself is a
    /// symlink. `dir_is_privileged` walks via `symlink_metadata`, so it judges the symlink on its
    /// own identity (never following it to a possibly-privileged target) and fails closed.
    #[cfg(unix)]
    #[test]
    fn a_symlink_component_is_never_privileged() {
        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("real");
        std::fs::create_dir(&target).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            !dir_is_privileged(&link),
            "a symlink path component must never be trusted, regardless of its target"
        );
    }

    /// Regression (#712): the walk reaches every ANCESTOR, so a user-writable parent condemns the
    /// whole path. A child dir under a world-writable parent is refused even though the child itself
    /// is not writable — proving `dir_is_privileged` no longer trusts a leaf under a weak ancestor.
    #[cfg(unix)]
    #[test]
    fn a_child_under_a_user_writable_parent_is_not_privileged() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let child = parent.path().join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            !dir_is_privileged(&child),
            "a non-writable child under a user-writable parent must not be trusted (ancestor walk)"
        );
    }

    /// The owner-SID policy accepts ONLY the well-known SYSTEM / BUILTIN\Administrators SIDs, by
    /// exact SID EQUALITY. A localized/display NAME is not a SID and never passes, and — the #565
    /// second-order fix — a lookalike group literally *named* "Administrators" (any other SID) is
    /// rejected, closing the old `\administrators` name-suffix match a domain group could satisfy.
    #[cfg(windows)]
    #[test]
    fn windows_owner_policy_accepts_only_the_well_known_system_or_administrators_sids() {
        use super::owner_sid_is_privileged;
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

    /// #712: `NT SERVICE\TrustedInstaller` — the fixed service SID that owns `C:\Program Files` and
    /// its protected subtree — MUST be accepted, or the ancestor walk would false-reject the
    /// canonical `%ProgramFiles%\DIG\bin` install root (whose `C:\Program Files` ancestor is
    /// TrustedInstaller-owned). The SID is a byte-identical constant on every Windows host.
    #[cfg(windows)]
    #[test]
    fn windows_owner_policy_accepts_the_trusted_installer_sid() {
        use super::{owner_sid_is_privileged, SID_TRUSTED_INSTALLER};
        assert!(owner_sid_is_privileged(SID_TRUSTED_INSTALLER));
        // Case/whitespace-insensitive, like the other well-known SIDs.
        assert!(owner_sid_is_privileged(&format!(
            "  {}  ",
            SID_TRUSTED_INSTALLER.to_ascii_lowercase()
        )));
    }

    /// #712: the PURE NTFS-attribute reparse test flags a symlink/junction/mount point (any component
    /// carrying `FILE_ATTRIBUTE_REPARSE_POINT`) and passes an ordinary directory. A reparse component
    /// anywhere in the chain redirects the whole path, so the walk rejects it before trusting the owner.
    #[cfg(windows)]
    #[test]
    fn windows_reparse_attribute_is_detected() {
        use super::attrs_are_reparse;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
        assert!(attrs_are_reparse(FILE_ATTRIBUTE_REPARSE_POINT));
        assert!(attrs_are_reparse(
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
        ));
        // An ordinary directory is not a reparse point.
        assert!(!attrs_are_reparse(FILE_ATTRIBUTE_DIRECTORY));
    }

    /// Regression (#565 LPE, second-order): the owner probe must NEVER execute a binary planted in
    /// the very directory it is classifying. A low-privilege user owns a tempdir (the user-writable
    /// root the gate must refuse) and plants a `powershell.exe` there; the SID-based probe must
    /// (a) read the tempdir's real owner (the non-privileged test user) and report NOT privileged,
    /// and (b) launch nothing — so the planted binary leaves no side effect. The old bare-name
    /// `Command::new("powershell")` resolved against the application directory, re-introducing
    /// exactly this LPE; the Win32-API probe spawns no process at all.
    #[cfg(windows)]
    #[test]
    fn windows_owner_probe_never_executes_a_planted_powershell_in_the_target_root() {
        use super::windows_owner_is_privileged;
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("pwned.txt");
        // A "powershell.exe" that, IF executed, would create the sentinel. (A .cmd payload behind
        // an .exe name suffices to prove execution; the probe must not run it either way.)
        std::fs::write(
            dir.path().join("powershell.exe"),
            format!("@echo off\r\n> \"{}\" echo pwned\r\n", sentinel.display()),
        )
        .unwrap();

        assert!(
            !windows_owner_is_privileged(dir.path()),
            "a user-owned directory must classify as NOT privileged"
        );
        assert!(
            !sentinel.exists(),
            "the owner probe must launch NO process — the planted powershell.exe must never run"
        );
    }
}
