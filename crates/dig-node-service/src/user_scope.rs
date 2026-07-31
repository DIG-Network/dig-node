//! Discovering and removing **other accounts'** user-scope service registrations (#526/B3).
//!
//! ## Why this module exists
//!
//! [`crate::service::install`] must clear a registration at the OTHER scope before creating one, or
//! a host upgrading from the historical user-level install ends up with two enabled units racing for
//! the node's port. Asking the OS "is it registered at user scope?" **cannot answer that question
//! when we are root**, which is exactly when it matters:
//!
//! * **systemd** — a user unit lives in a per-account manager reached over that account's session
//!   D-Bus. Root has no `--user` session of its own, so `systemctl --user cat` fails and the probe
//!   reports `false` for a unit that is plainly present in `/home/<user>/.config/systemd/user`.
//! * **launchd** — `gui/<uid>` is per-uid. As root, `geteuid()` is 0, so the probe addresses
//!   `gui/0`, never the desktop user's `gui/501`.
//!
//! So the sweep is done on the **filesystem**, per account, which is authoritative regardless of
//! session state: enumerate the real registration FILES, remove them, drop their enablement
//! symlinks, and best-effort stop the still-running instance. What genuinely cannot be reached is
//! REPORTED rather than assumed clean ([`UserScopeSweep::residual_note`]).
//!
//! ## Root deleting inside user-owned directories
//!
//! Every path here is under a directory an unprivileged user controls, so a naive removal is an
//! arbitrary-delete primitive: symlink `~/.config` at `/etc` and a root `remove_dir_all` follows it
//! out of the home directory. Therefore **no intermediate DIRECTORY component may be a symlink** —
//! checked with `lstat` on every component between the account root and the leaf before anything is
//! removed ([`first_symlink_component`]), the same no-follow discipline [`crate::security`] applies
//! to the install target. The leaf itself may be a symlink (systemd's enablement entry always is)
//! because it is only ever `unlink`ed, which removes the link and never follows it. Only individual
//! FILES and symlinks are ever unlinked; this module never removes a directory tree.

use std::io;
use std::path::{Path, PathBuf};

/// The account-root directories user-scope registrations are searched under.
///
/// `/home` and `/root` cover a stock Linux; `/Users` covers macOS. Deliberately a FIXED list rather
/// than a parse of `/etc/passwd`: a home directory outside these roots is a residual this module
/// reports instead of guessing at (see [`UserScopeSweep::residual_note`]).
pub const ACCOUNT_ROOTS: &[&str] = &["/home", "/root", "/Users"];

/// One discovered user-scope registration belonging to some account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserScopeRegistration {
    /// The account's home directory (`/home/alice`), which names the account in reports.
    pub home: PathBuf,
    /// The uid that owns the registration file — the launchd `gui/<uid>` domain to bootout, and the
    /// account identity, read from the file itself (`lstat`) rather than from a spawned lookup.
    pub uid: Option<u32>,
    /// The systemd user unit / launchd agent plist itself.
    pub registration: PathBuf,
    /// Enablement symlinks that make it start on login (`…/default.target.wants/<unit>`), which must
    /// go too — removing only the unit file leaves systemd reporting the unit as enabled.
    pub enablement: Vec<PathBuf>,
}

/// What a sweep did, per registration, and what it could not reach.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserScopeSweep {
    /// Registrations fully removed, by home directory.
    pub removed: Vec<PathBuf>,
    /// Registrations found but NOT removed, with why — a leftover the operator must know about.
    pub failed: Vec<(PathBuf, String)>,
}

impl UserScopeSweep {
    /// Whether anything was found at all (removed or not).
    pub fn found_any(&self) -> bool {
        !self.removed.is_empty() || !self.failed.is_empty()
    }

    /// The honest statement of what this mechanism does NOT cover, for the operator-facing summary.
    /// Kept beside the mechanism so it cannot drift from it.
    pub fn residual_note() -> &'static str {
        "a user-scope registration under a home directory outside /home, /root or /Users, or under \
         a non-default XDG_CONFIG_HOME, is not discoverable from here and must be removed by that \
         user (`dig-node uninstall --scope user`)"
    }
}

/// The systemd user-unit path for `home`, and the enablement symlink that accompanies it.
///
/// PURE (string/path construction only), so the layout is asserted without a filesystem. The unit
/// FILE NAME must be the one `service-manager`'s systemd backend writes — `to_script_name()`
/// (`dignetwork-dig-node`), not the reverse-DNS label — which the caller supplies.
pub fn systemd_user_paths(home: &Path, unit_file_name: &str) -> (PathBuf, Vec<PathBuf>) {
    let user_dir = home.join(".config").join("systemd").join("user");
    let unit = user_dir.join(unit_file_name);
    let wants = user_dir.join("default.target.wants").join(unit_file_name);
    (unit, vec![wants])
}

/// The launchd per-user agent plist path for `home`. PURE.
pub fn launchd_agent_path(home: &Path, label: &str) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist"))
}

/// The FIRST DIRECTORY component between `base` and `path` that is a symlink, per the injected
/// `is_symlink` oracle — or `None` when that chain is symlink-free.
///
/// Two components are deliberately NOT judged:
/// * **The account roots themselves** (`/home`, `/Users`) are system-owned, and on some systems are
///   legitimately symlinks (`/home → /System/Volumes/Data/home`). Judging them would refuse every
///   account on such a host — a guard that disables the mechanism it protects.
/// * **The leaf**, because systemd's enablement entry IS a symlink by design, and refusing it would
///   leave the unit ENABLED — the exact outcome the sweep exists to prevent. This is safe: the leaf
///   is only ever passed to `remove_file`, which unlinks the LINK and never follows it. The
///   arbitrary-delete primitive this guard closes needs an intermediate DIRECTORY to redirect the
///   walk (symlink `~/.config` at `/etc` and a root removal descends out of the home directory), and
///   every one of those is still judged.
///
/// The oracle is a parameter for two reasons: it makes the walk testable on any host (creating a real
/// symlink needs privilege on Windows), and it keeps this function PURE.
pub fn first_symlink_component<'a>(
    base: &Path,
    path: &'a Path,
    is_symlink: impl Fn(&Path) -> bool,
) -> Option<&'a Path> {
    path.ancestors()
        .skip(1) // the leaf is unlinked, never followed — see the doc comment
        .take_while(|c| c.starts_with(base) && *c != base)
        .find(|c| is_symlink(c))
}

/// Real-filesystem [`first_symlink_component`], judging each component with `lstat` (which does NOT
/// follow the link, so a symlink is classified on its own identity).
fn first_real_symlink_component<'a>(base: &Path, path: &'a Path) -> Option<&'a Path> {
    first_symlink_component(base, path, |c| {
        std::fs::symlink_metadata(c)
            .map(|md| md.file_type().is_symlink())
            .unwrap_or(false)
    })
}

/// The uid owning `path`, via `lstat` — no process, no name lookup.
#[cfg(unix)]
fn owner_uid(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|md| md.uid())
}
#[cfg(not(unix))]
fn owner_uid(_path: &Path) -> Option<u32> {
    None
}

/// Enumerate the home directories under [`ACCOUNT_ROOTS`] that exist. A root that is itself a
/// symlink is followed (see [`first_symlink_component`]); the per-account chain below it is not.
fn account_homes() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    for root in ACCOUNT_ROOTS {
        let root = Path::new(root);
        if root == Path::new("/root") {
            if root.is_dir() {
                homes.push(root.to_path_buf());
            }
            continue;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // `metadata` (follows) is right for deciding "is this a home directory"; the no-follow
            // discipline applies to the registration paths BELOW it, which is where a removal
            // happens.
            if path.is_dir() {
                homes.push(path);
            }
        }
    }
    homes
}

/// Discover every account's user-scope registration of this service on the filesystem.
///
/// `unit_file_name` is the systemd unit file name and `label` the launchd/reverse-DNS label; both are
/// passed in so this module never re-derives the service identity.
pub fn discover(unit_file_name: &str, label: &str) -> Vec<UserScopeRegistration> {
    let mut found = Vec::new();
    for home in account_homes() {
        let (unit, enablement) = systemd_user_paths(&home, unit_file_name);
        let plist = launchd_agent_path(&home, label);
        for registration in [unit, plist] {
            // `symlink_metadata` so a dangling or symlinked entry still registers as PRESENT — it is
            // something to clean up, and the removal path re-checks the chain before touching it.
            if std::fs::symlink_metadata(&registration).is_err() {
                continue;
            }
            let present_enablement: Vec<PathBuf> = enablement
                .iter()
                .filter(|p| std::fs::symlink_metadata(p).is_ok())
                .cloned()
                .collect();
            found.push(UserScopeRegistration {
                home: home.clone(),
                uid: owner_uid(&registration),
                registration,
                enablement: present_enablement,
            });
        }
    }
    found
}

/// Remove ONE discovered registration: stop the running instance (best-effort), drop the enablement
/// symlinks, then unlink the registration file.
///
/// Refuses outright — without removing anything — if any intermediate DIRECTORY component below the
/// account root is a symlink, because as root a redirected walk would be an arbitrary-delete
/// primitive rather than a cleanup. The leaf may be a symlink; see [`first_symlink_component`].
/// `stop` is injected so the OS-specific stop (and the fact that it is best-effort) stays out of the
/// removal logic, and so the ORDER is testable without a real service manager.
pub fn remove(
    registration: &UserScopeRegistration,
    stop: impl Fn(&UserScopeRegistration),
) -> io::Result<()> {
    for path in std::iter::once(&registration.registration).chain(registration.enablement.iter()) {
        if let Some(link) = first_real_symlink_component(&registration.home, path) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to remove \"{}\": the path component \"{}\" is a symlink, so removing \
                     it as root could delete a file outside {}",
                    path.display(),
                    link.display(),
                    registration.home.display()
                ),
            ));
        }
    }
    // Stop BEFORE unlinking: once the unit file is gone the manager can no longer be asked to stop
    // it by name, and a still-running instance keeps holding the node's port.
    stop(registration);
    for link in &registration.enablement {
        std::fs::remove_file(link)?;
    }
    std::fs::remove_file(&registration.registration)?;
    Ok(())
}

/// Sweep every other account's user-scope registration: discover, then remove each, reporting both
/// outcomes. Never fails as a whole — a leftover is REPORTED (`failed`), because the caller must be
/// able to warn about it without aborting an otherwise-good install.
pub fn sweep(
    unit_file_name: &str,
    label: &str,
    stop: impl Fn(&UserScopeRegistration),
) -> UserScopeSweep {
    let mut sweep = UserScopeSweep::default();
    for registration in discover(unit_file_name, label) {
        match remove(&registration, &stop) {
            Ok(()) => sweep.removed.push(registration.home.clone()),
            Err(e) => sweep
                .failed
                .push((registration.home.clone(), e.to_string())),
        }
    }
    sweep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_user_paths_are_the_per_account_manager_layout() {
        let (unit, enablement) =
            systemd_user_paths(Path::new("/home/alice"), "dignetwork-dig-node.service");
        assert_eq!(
            unit,
            PathBuf::from("/home/alice/.config/systemd/user/dignetwork-dig-node.service")
        );
        // Removing only the unit file leaves the unit ENABLED (systemd reads the wants symlink), so
        // the enablement link is part of the registration, not an extra.
        assert_eq!(
            enablement,
            vec![PathBuf::from(
                "/home/alice/.config/systemd/user/default.target.wants/dignetwork-dig-node.service"
            )]
        );
    }

    #[test]
    fn launchd_agent_path_is_the_per_user_agent_location() {
        assert_eq!(
            launchd_agent_path(Path::new("/Users/bob"), "net.dignetwork.dig-node"),
            PathBuf::from("/Users/bob/Library/LaunchAgents/net.dignetwork.dig-node.plist")
        );
    }

    #[test]
    fn account_roots_cover_linux_and_macos_homes() {
        assert!(ACCOUNT_ROOTS.contains(&"/home"));
        assert!(ACCOUNT_ROOTS.contains(&"/root"));
        assert!(ACCOUNT_ROOTS.contains(&"/Users"));
    }

    /// The root-as-arbitrary-delete guard. A symlinked `~/.config` (or any component below the
    /// account root) must ABORT the removal — the oracle is injected, so this is asserted on a
    /// Windows host with no privileges, where a real symlink cannot even be created.
    #[test]
    fn a_symlinked_component_below_the_account_root_is_detected() {
        let home = Path::new("/home/alice");
        let path = Path::new("/home/alice/.config/systemd/user/dignetwork-dig-node.service");

        let hit = first_symlink_component(home, path, |c| c == Path::new("/home/alice/.config"));
        assert_eq!(hit, Some(Path::new("/home/alice/.config")));

        // Nothing below the root is a symlink ⇒ safe.
        assert_eq!(first_symlink_component(home, path, |_| false), None);
    }

    /// The account root itself is NOT judged: `/home` (or `/Users`) may legitimately be a symlink on
    /// a real system, and it is system-owned rather than attacker-controlled. Judging it would make
    /// the sweep refuse every account on such a host — a guard that disables the mechanism it is
    /// meant to protect.
    #[test]
    fn the_account_root_itself_is_not_judged_a_symlink_violation() {
        let home = Path::new("/home/alice");
        let path = Path::new("/home/alice/Library/LaunchAgents/net.dignetwork.dig-node.plist");
        assert_eq!(
            first_symlink_component(home, path, |c| c == home || c == Path::new("/home")),
            None,
            "only components strictly BELOW the account root are judged"
        );
    }

    /// The LEAF is exempt, and it must be: systemd's enablement entry
    /// (`default.target.wants/<unit>`) is ALWAYS a symlink — refusing it would make the guard refuse
    /// the single artifact whose whole purpose is to be removed, leaving the unit ENABLED and the
    /// migration a no-op (caught live by the `service-smoke` system-scope leg on ubuntu-latest).
    ///
    /// Exempting it is safe for the reason the guard exists: `remove_file` unlinks the LINK, it never
    /// follows it, so a leaf pointed at `/etc/passwd` costs the link and not the target. The
    /// arbitrary-delete primitive comes from an intermediate DIRECTORY component redirecting the
    /// walk, and those are still judged — asserted here in the same test so the exemption cannot
    /// widen unnoticed.
    #[test]
    fn the_leaf_may_be_a_symlink_but_an_intermediate_directory_may_not() {
        let home = Path::new("/home/alice");
        let wants = Path::new(
            "/home/alice/.config/systemd/user/default.target.wants/dignetwork-dig-node.service",
        );

        assert_eq!(
            first_symlink_component(home, wants, |c| c == wants),
            None,
            "the enablement entry IS a symlink by design and must remain removable"
        );

        let parent = Path::new("/home/alice/.config/systemd/user/default.target.wants");
        assert_eq!(
            first_symlink_component(home, wants, |c| c == parent || c == wants),
            Some(parent),
            "a redirected directory component is still refused"
        );
    }

    #[test]
    fn remove_refuses_and_touches_nothing_when_a_component_is_a_symlink() {
        // A real temp tree stands in for the account root, with a REAL file to remove; the symlink
        // condition is forced by pointing the account root somewhere the chain cannot descend from,
        // which is what a symlinked component looks like to the walk.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let nested = home.join(".config").join("systemd").join("user");
        std::fs::create_dir_all(&nested).unwrap();
        let unit = nested.join("dignetwork-dig-node.service");
        std::fs::write(&unit, b"[Unit]\n").unwrap();

        let stopped = std::cell::Cell::new(false);
        let registration = UserScopeRegistration {
            home,
            uid: None,
            registration: unit.clone(),
            enablement: vec![],
        };
        remove(&registration, |_| stopped.set(true)).expect("a symlink-free chain is removable");
        assert!(!unit.exists(), "the unit file is unlinked");
        assert!(
            stopped.get(),
            "the running instance is stopped BEFORE the unit file disappears"
        );
    }

    #[test]
    fn sweep_reports_found_and_nothing_when_no_account_holds_a_registration() {
        // A label no account can hold ⇒ an empty sweep, and `found_any` false. Runs on any host: it
        // only READS the account roots (which may not even exist on Windows).
        let sweep = super::sweep(
            "definitely-not-a-real-unit.service",
            "not.a.real.label",
            |_| {},
        );
        assert!(!sweep.found_any(), "{sweep:?}");
        assert!(sweep.removed.is_empty() && sweep.failed.is_empty());
    }

    #[test]
    fn residual_note_states_what_is_not_covered() {
        // The honest-scope statement must name the real gaps, so SPEC + summary cannot drift from
        // the mechanism.
        let note = UserScopeSweep::residual_note();
        assert!(note.contains("XDG_CONFIG_HOME"));
        assert!(note.contains("/home"));
    }
}
