//! At-rest decision primitives shared by every seam that mints key material (#1285 W1a shape,
//! dig_ecosystem#2168).
//!
//! Two operations, both of which exist because the obvious standard-library call is wrong for a
//! secret: deciding whether an artifact is there ([`presence`]), and putting one there without
//! clobbering a concurrent writer ([`write_new_owner_only`]).
//!
//! This module is the canonical home so the node has ONE implementation. `dig-wallet`'s
//! `autoseed` established both shapes first, and its threat model and named tests still document
//! them in the wallet's own terms; the definitions live here because `dig-wallet` depends on
//! `dig-node-core` and not the other way round.

use std::fs;
use std::io;
use std::path::Path;

/// Whether an artifact is on disk.
///
/// Deliberately not `bool`: the third answer — *we could not tell* — is the one that matters, and
/// it lives in the `Err` of [`presence`] rather than being folded into a variant nobody checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// The artifact is there.
    Present,
    /// The artifact is definitively not there.
    Absent,
}

/// Answer whether `path` exists, treating "the question could not be answered" as an ERROR rather
/// than as "no".
///
/// This exists because [`Path::exists`] does not. `exists()` is `fs::metadata(..).is_ok()`, which
/// collapses every metadata failure — permission denied, a locked file, a sharing violation from
/// an AV/EDR scanner, a roaming-profile sync, an ACL changed by an OS update, `EIO`, `EMFILE`, an
/// unmounted volume — into a plain `false`.
///
/// That is harmless while the answer only chooses which screen to render. It stops being harmless
/// the moment a `false` causes key material to be **minted**, because minting overwrites: the
/// caller asked "is there already an identity here?", was told "no" by a transient I/O error, and
/// replaced the real one. **An unreadable path is not an absent one**, and this function refuses to
/// say it is.
///
/// # Errors
/// The underlying [`Path::try_exists`] error when existence cannot be determined.
pub fn presence(path: &Path) -> io::Result<Presence> {
    if path.try_exists()? {
        Ok(Presence::Present)
    } else {
        Ok(Presence::Absent)
    }
}

/// Write `bytes` to `path`, creating the file **exclusively** and readable only by its owner.
///
/// Three properties, all required:
///
/// - **Create-new.** `create_new` is the atomic test-and-set the OS already provides. Two
///   processes starting at once cannot both succeed, so neither can clobber the other's key
///   material; the loser gets [`io::ErrorKind::AlreadyExists`] and is expected to ADOPT the
///   winner's file rather than retry. A `presence()` check followed by a plain write is not the
///   same thing — that is a TOCTOU race, and the window is exactly a concurrent start.
/// - **Owner-only from the first byte.** On Unix the mode is set at `open` time rather than by a
///   later `chmod`, because the window between the two is real and the file has a secret in it.
///   **On Windows the file inherits the profile ACL**; this function does not install an explicit
///   DACL, and callers must not claim that it does.
/// - **Fail closed.** A partially-written file is removed before the error propagates, so a
///   truncated secret is never left behind to be read back as if it were whole.
///
/// # Errors
/// [`io::ErrorKind::AlreadyExists`] if `path` is already there — a normal, expected outcome that
/// the caller resolves by reading it — or any other I/O error from creating or writing the file.
pub fn write_new_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(path)?;
    let written = {
        use io::Write as _;
        file.write_all(bytes).and_then(|()| file.sync_all())
    };
    if let Err(e) = written {
        drop(file);
        // Never leave a truncated secret at a path a later read would treat as complete.
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}
