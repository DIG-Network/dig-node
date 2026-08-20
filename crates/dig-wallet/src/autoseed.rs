//! Unattended wallet bootstrap — mint a seed on first start, fail closed on everything else (#277).
//!
//! The node must be usable the moment it is installed, so on every start it checks whether a
//! mnemonic seed exists and mints one if it does not. There is no user in this path: no prompt,
//! no password, no interaction. A user who wants their own recovery phrase replaces the minted
//! wallet later through the ordinary import path, which this module does not special-case.
//!
//! # At rest — a device key, deliberately not next to the wallet
//!
//! An auto-created seed is sealed in the same [`dig_keystore::opaque`] `DIGOP1` container an
//! imported seed uses (Argon2id + AES-256-GCM). Only the key differs: an imported seed is sealed
//! under the user's password, an auto-created one under a 32-byte CSPRNG **device key** held in
//! [`WalletPaths::device_key`].
//!
//! The OS credential store is NOT used, and that is not a preference — `dig-keystore` documents it
//! as forbidden here. Its `backend/os_keychain.rs` states that the store is released by the *login
//! session*, so a machine service running as SYSTEM or a non-interactive account has no session to
//! release it and MUST NOT use that backend; the same file excludes Linux entirely (`open` returns
//! `None`, with no fallback), and headless Linux is a primary dig-node target. One code path on
//! every platform is worth more here than a per-platform ladder whose weakest rung is the one that
//! actually runs on the hosts we care about.
//!
//! # What this protects, and what it plainly does not
//!
//! This protects the seed from leaving the machine by accident. It does **not** protect it from an
//! attacker already on the machine as this user. Those are not the same claim and no sentence in
//! this repo may blur them:
//!
//! - **Defended:** a backup, sync client, snapshot, container image layer, support archive or
//!   diagnostic bundle that scoops the wallet directory. It gets ciphertext, because the device key
//!   is not in that directory.
//! - **NOT defended:** local code execution as the node's user, a full-disk image, or root. Both
//!   files sit on one volume; whoever takes the volume takes both.
//!
//! # The device key is a SIBLING of the wallet directory, never a child
//!
//! [`WalletPaths::resolve`] puts the device key under `DigNode/device/`, beside `DigWallet/` rather
//! than inside it. **That placement is the entire partial-exfiltration boundary.** Collapse the two
//! directories together — as a tidying commit reasonably might, since they are always used together
//! — and the seal degrades to a well-known-password seal with extra steps: a file that still
//! carries the `DIGOP1` magic, still passes any "is it encrypted at rest" check, and protects
//! nothing, because the one artifact that opens it travels with it. That is strictly worse than
//! plaintext, since the next reader trusts the format and stops looking.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use dig_keystore::{opaque, KdfParams, Password};
use digstore_chain::seed::generate_mnemonic;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::seed_store;

/// Bytes of a device key. Fixed by the CSPRNG draw, not by any format field.
const DEVICE_KEY_LEN: usize = 32;

/// Word count for a minted phrase — the same 24 the explicit create path uses, so an auto-created
/// wallet and a user-created one are the same kind of wallet.
const MNEMONIC_WORDS: usize = 24;

// -- Paths ---------------------------------------------------------------------------------------

/// Where the three bootstrap artifacts live.
///
/// Carried as a value rather than read from the environment at each use so the whole bootstrap is
/// exercisable against a temporary directory, including the failure arms — the arms are the part
/// most worth testing and the part least likely to be reachable through process-wide state.
#[derive(Clone, Debug)]
pub struct WalletPaths {
    /// The sealed mnemonic — the existing `seed_path()` file, format unchanged.
    pub seed: PathBuf,
    /// The 32-byte raw device key. See the module docs: this MUST NOT move under the seed's
    /// directory.
    pub device_key: PathBuf,
    /// Origin/lifecycle facts about the seed. Never contains key material.
    pub meta: PathBuf,
}

impl WalletPaths {
    /// Resolve the production layout: the seed and its metadata under `DigWallet/`, the device key
    /// under the sibling `DigNode/device/`.
    ///
    /// Both roots derive from the same per-user base the wallet already used (`%LOCALAPPDATA%`,
    /// falling back to `$HOME`), so this adds no new location contract — only the split.
    pub fn resolve(seed: PathBuf) -> Self {
        let meta = sibling(&seed, "wallet.meta.json");
        let device_key = user_base()
            .join("DigNode")
            .join("device")
            .join("device.key");
        Self {
            seed,
            device_key,
            meta,
        }
    }
}

/// The production layout, rooted at the wallet's existing seed location.
///
/// The one entry point a host binary needs: it keeps the seed's own path a private detail of this
/// crate, so no caller can drift onto a second spelling of it.
pub fn default_paths() -> WalletPaths {
    WalletPaths::resolve(crate::seed_path())
}

/// The per-user, non-roaming base directory both roots hang off (NC-3's location contract).
fn user_base() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base)
}

/// A path beside `path`, keeping its directory. Falls back to a bare relative name only when
/// `path` has no parent at all, matching what the wallet's other sidecar files already do.
fn sibling(path: &Path, name: &str) -> PathBuf {
    path.parent()
        .map(|p| p.join(name))
        .unwrap_or_else(|| PathBuf::from(name))
}

// -- Presence ------------------------------------------------------------------------------------

/// Whether an artifact is on disk. Deliberately not `bool`: the third answer — *we could not tell*
/// — is the one that matters, and it lives in the `Err` of [`presence`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    Present,
    Absent,
}

/// Answer whether `path` exists, treating "the question could not be answered" as an ERROR rather
/// than as "no".
///
/// This exists because [`Path::exists`] does not. `exists()` collapses every metadata failure —
/// permission denied, a locked file, a transient I/O error, an unmounted volume, an ACL that
/// changed under an OS update — into a plain `false`. That was harmless while the answer only
/// chose which screen to render. It stops being harmless the moment a `false` causes a wallet to
/// be *minted*, because the seed IS the wallet: overwriting one is unrecoverable, unundoable, and
/// the funds are gone. An unreadable path is not an absent one, and this function refuses to say
/// it is.
pub fn presence(path: &Path) -> io::Result<Presence> {
    if path.try_exists()? {
        Ok(Presence::Present)
    } else {
        Ok(Presence::Absent)
    }
}

// -- Device key ----------------------------------------------------------------------------------

/// A 32-byte machine-held key that seals an auto-created seed.
///
/// No `Debug`, no `Display`, no `Serialize` — not an oversight and not to be added. The type must
/// be impossible to log, format into an error, or carry in a panic payload.
pub struct DeviceKey(Zeroizing<[u8; DEVICE_KEY_LEN]>);

impl DeviceKey {
    /// The key rendered as the `Password` the `opaque` container seals under: lowercase hex, the
    /// same convention the ecosystem's other machine-key boundary uses. Hex rather than raw bytes
    /// so the value is a well-formed string at every layer it crosses.
    fn as_password(&self) -> Password {
        Password::from(Zeroizing::new(hex::encode(&self.0[..])).to_string())
    }
}

/// Why a device key could not be established. Every arm is fail-closed; none of them writes.
#[derive(Debug)]
pub enum DeviceKeyError {
    /// The key file could not be read or its existence could not be determined.
    Unreadable(io::Error),
    /// The file exists but is not 32 bytes — refuse rather than stretch or truncate it into
    /// something that would silently open nothing.
    Malformed,
    /// A seed exists and the device key does not. See [`BootstrapState::Orphaned`].
    Orphaned,
    /// The key could not be created, or its permissions could not be established.
    NotCreated(io::Error),
}

/// Read the device key at `path`, or mint one if `allow_create` and none exists.
///
/// `allow_create` is a parameter rather than an internal decision because the caller holds the fact
/// that decides it: whether a seed already exists. Minting a key beside an existing seed produces a
/// key that cannot open it, which converts a recoverable operator mistake into permanent loss.
fn load_device_key(path: &Path, allow_create: bool) -> Result<DeviceKey, DeviceKeyError> {
    match presence(path).map_err(DeviceKeyError::Unreadable)? {
        Presence::Present => {
            let bytes = fs::read(path).map_err(DeviceKeyError::Unreadable)?;
            let bytes = Zeroizing::new(bytes);
            let exact: [u8; DEVICE_KEY_LEN] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| DeviceKeyError::Malformed)?;
            Ok(DeviceKey(Zeroizing::new(exact)))
        }
        Presence::Absent if allow_create => mint_device_key(path),
        Presence::Absent => Err(DeviceKeyError::Orphaned),
    }
}

/// Draw 32 bytes from the OS CSPRNG and persist them owner-only, create-new.
fn mint_device_key(path: &Path) -> Result<DeviceKey, DeviceKeyError> {
    let mut key = Zeroizing::new([0u8; DEVICE_KEY_LEN]);
    getrandom::getrandom(key.as_mut())
        .map_err(|e| DeviceKeyError::NotCreated(io::Error::other(e.to_string())))?;

    match write_new_owner_only(path, key.as_ref()) {
        Ok(()) => Ok(DeviceKey(key)),
        // Another process won the race and wrote its own key. Its key is the real one — the seed
        // it is about to write is sealed under it. Adopt the winner rather than clobbering it.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            load_device_key(path, false).map_err(|_| DeviceKeyError::NotCreated(e))
        }
        Err(e) => Err(DeviceKeyError::NotCreated(e)),
    }
}

// -- Metadata ------------------------------------------------------------------------------------

/// How the seed came to exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeedOrigin {
    /// Machine-created; the 24 words have never been shown to a human.
    Auto,
    /// Machine-created, and the user has since been shown the phrase.
    AutoAcknowledged,
    /// Created through the explicit import path. Untouched by any of this.
    Imported,
}

/// Origin and lifecycle facts about the seed. Never key material — this file is readable without
/// unlocking anything, exactly like the wallet's other sidecars.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletMeta {
    pub origin: SeedOrigin,
    /// RFC 3339, as an opaque string — this is a record, not an input to any decision.
    pub created_at: String,
    /// Set the first time a balance read returns non-zero, and NEVER cleared. See
    /// [`WalletMeta::is_disposable`].
    pub ever_funded: bool,
}

impl WalletMeta {
    /// Whether any surface may describe this wallet as disposable.
    ///
    /// A wallet the user never chose to create is genuinely disposable on day one and is custody on
    /// some later day, and nothing may silently keep treating it as the former after that
    /// transition. Two rules make that safe:
    ///
    /// - `ever_funded` is a **monotonic latch**, evaluated on first observation rather than on the
    ///   current balance. A balance that reads zero because the node is offline, or is momentarily
    ///   zero between spends, is not evidence the wallet never mattered.
    /// - An **absent or unreadable** metadata file answers `false` (see [`read_meta`]), because the
    ///   dangerous direction of this question is the one that discards funds.
    pub fn is_disposable(&self) -> bool {
        self.origin == SeedOrigin::Auto && !self.ever_funded
    }

    /// Latch the funded flag. Monotonic by construction: there is no code path that clears it.
    pub fn mark_ever_funded(&mut self) {
        self.ever_funded = true;
    }
}

/// Open a sealed seed under a device key given in the hex form [`password_str`] produces.
///
/// The read half of the bootstrap, exposed so a host binary can name the phrase a given run
/// actually created — which is what lets its never-log battery assert on the REAL material rather
/// than on an invented sentinel the bootstrap could never have logged.
pub fn open_sealed_with_device_key(
    sealed: &[u8],
    device_key_hex: &str,
) -> Result<Zeroizing<String>, String> {
    seed_store::decrypt_seed(sealed, device_key_hex)
}

/// Read the sidecar, or `None` when it is absent, unreadable or unparsable.
///
/// Callers must treat `None` as "not disposable" rather than as "auto" — an existing seed with no
/// readable metadata is far more likely to be an imported wallet predating this file than a minted
/// one, and mislabelling an imported wallet as disposable is the expensive direction of that guess.
pub fn read_meta(path: &Path) -> Option<WalletMeta> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Whether the wallet at `paths` may be described as disposable. Fails closed to `false` on any
/// doubt, including an entirely absent sidecar.
pub fn is_disposable(paths: &WalletPaths) -> bool {
    read_meta(&paths.meta).is_some_and(|m| m.is_disposable())
}

/// RFC 3339 timestamp for the creation record.
fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

// -- Bootstrap -----------------------------------------------------------------------------------

/// What the bootstrap found or did. Every variant except [`Created`](BootstrapState::Created)
/// wrote nothing.
#[derive(Debug, PartialEq, Eq)]
pub enum BootstrapState {
    /// No seed existed; one was minted and is now on disk, sealed under the device key.
    Created,
    /// A seed existed and opened under the device key.
    Opened,
    /// A seed existed and did NOT open under the device key — an imported wallet sealed under the
    /// user's password, a legacy-format file, or a corrupt one. It is left exactly as found: a file
    /// that fails to decrypt is still evidence that a wallet exists, and that is precisely the
    /// state in which its owner most needs it untouched.
    Locked,
    /// A seed exists and the device key is gone. **Nothing is minted in this state.** A fresh key
    /// cannot open the existing seed, so minting one would present an empty new wallet as though it
    /// were the user's — turning a wrong mount, a half-restored backup or a container missing a
    /// volume into permanent, silent loss.
    Orphaned,
}

/// Why the bootstrap refused. The node runs wallet-less and says so; there is deliberately no
/// fallback, because a fallback to plaintext would make plaintext the real design on exactly the
/// constrained hosts this is meant to serve.
#[derive(Debug)]
pub enum BootstrapError {
    /// The seed path's existence could not be determined. Nothing was created.
    SeedPathUnreadable(io::Error),
    /// The device key could not be established.
    DeviceKey(DeviceKeyError),
    /// The seed could not be minted, sealed or persisted with the permissions it requires.
    NotCreated(String),
}

/// Ensure a usable wallet seed exists, minting one if and only if there is definitely none.
///
/// Ordering is load-bearing in two places:
///
/// - **Seed presence is probed first**, because the device-key decision depends on it: a key may be
///   minted only when there is no seed to orphan.
/// - **The device key is written before the seed**, so a crash between the two leaves an unused
///   device key — harmless, and reused on the next boot. The reverse order can leave a seed nothing
///   can ever open.
pub fn ensure_wallet(paths: &WalletPaths) -> Result<BootstrapState, BootstrapError> {
    let seed_there = presence(&paths.seed).map_err(BootstrapError::SeedPathUnreadable)?;

    let key = load_device_key(&paths.device_key, seed_there == Presence::Absent).map_err(|e| {
        match e {
            DeviceKeyError::Orphaned => BootstrapError::DeviceKey(DeviceKeyError::Orphaned),
            other => BootstrapError::DeviceKey(other),
        }
    });

    let key = match key {
        Ok(k) => k,
        Err(BootstrapError::DeviceKey(DeviceKeyError::Orphaned)) => {
            return Ok(BootstrapState::Orphaned)
        }
        Err(e) => return Err(e),
    };

    if seed_there == Presence::Present {
        return Ok(open_existing(paths, &key));
    }

    mint_seed(paths, &key)
}

/// Try the existing seed against the device key, writing nothing either way.
fn open_existing(paths: &WalletPaths, key: &DeviceKey) -> BootstrapState {
    match fs::read(&paths.seed) {
        Ok(bytes) => match seed_store::decrypt_seed(&bytes, &password_str(key)) {
            Ok(_) => BootstrapState::Opened,
            Err(_) => BootstrapState::Locked,
        },
        // Present a moment ago, unreadable now. Still not grounds to write.
        Err(_) => BootstrapState::Locked,
    }
}

/// Mint a 24-word phrase, seal it under the device key, and persist it create-new.
fn mint_seed(paths: &WalletPaths, key: &DeviceKey) -> Result<BootstrapState, BootstrapError> {
    let mnemonic = generate_mnemonic(MNEMONIC_WORDS)
        .map_err(|e| BootstrapError::NotCreated(format!("generate mnemonic: {e}")))?;
    let phrase = Zeroizing::new(mnemonic.to_string());

    let sealed = opaque::seal(
        &key.as_password(),
        phrase.as_bytes(),
        KdfParams::default(),
    )
    .map_err(|e| BootstrapError::NotCreated(format!("seal seed: {e}")))?;

    match write_new_owner_only(&paths.seed, &sealed) {
        Ok(()) => {
            write_meta(paths);
            Ok(BootstrapState::Created)
        }
        // Another process won the startup race. Its seed is the wallet now; ours is discarded
        // unwritten. Do NOT delete anything and do NOT retry — re-read the winner.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(open_existing(paths, key)),
        Err(e) => Err(BootstrapError::NotCreated(format!("write seed: {e}"))),
    }
}

/// Record the origin sidecar. Best-effort ON PURPOSE: the seed is already on disk at this point and
/// deleting it to keep a bookkeeping file consistent would destroy key material to preserve a note
/// about it. A missing sidecar reads as "not disposable" ([`read_meta`]), which is the safe
/// direction, so the failure degrades into extra caution rather than into risk.
fn write_meta(paths: &WalletPaths) {
    let meta = WalletMeta {
        origin: SeedOrigin::Auto,
        created_at: now_rfc3339(),
        ever_funded: false,
    };
    if let Ok(json) = serde_json::to_vec_pretty(&meta) {
        let _ = write_new_owner_only(&paths.meta, &json);
    }
}

/// The device key in the string form `seed_store` takes. Kept in one place so the hex convention
/// cannot drift between sealing and opening.
fn password_str(key: &DeviceKey) -> String {
    hex::encode(&key.0[..])
}

// -- Owner-only, create-new writes -----------------------------------------------------------

/// Write `bytes` to `path`, creating the file exclusively and readable only by its owner.
///
/// Three properties, all required:
///
/// - **Create-new.** `create_new` is the atomic test-and-set the OS already provides; two nodes
///   starting at once cannot both succeed, so neither can clobber the other's key material. The
///   loser gets `AlreadyExists` and adopts the winner's file.
/// - **Owner-only from the first byte.** On Unix the mode is set at `open` time rather than by a
///   later `chmod`, because the window between the two is real and the file has a secret in it.
/// - **Fail closed on permissions.** If ownership cannot be established the partially-created file
///   is removed and the error propagates. A secret is never left at a path whose permissions could
///   not be proven.
fn write_new_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
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

    if let Err(e) = harden_owner_only(path).and_then(|()| {
        use io::Write as _;
        file.write_all(bytes)?;
        file.sync_all()
    }) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// Replace `path`'s inherited ACL with a protected, owner-only one.
///
/// Unix needs nothing here — the mode was set at `open` time, which is strictly better than a
/// post-hoc `chmod`.
#[cfg(not(windows))]
fn harden_owner_only(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Windows: install an explicit `D:P(A;;FA;;;<user>)` DACL — full access for this process's user
/// and nobody else, with inheritance blocked.
///
/// The inherited `%LOCALAPPDATA%` ACL is NOT relied on. It is per-user by convention rather than by
/// guarantee, a Unix `0600` does not translate onto it, and an ACL inherited today can be widened
/// by an administrator or a profile-policy change tomorrow without this code ever running again.
#[cfg(windows)]
fn harden_owner_only(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let sid = current_user_sid_string()?;
    let sddl = wide(&format!("D:P(A;;FA;;;{sid})"));

    let mut descriptor = std::ptr::null_mut();
    // SAFETY: `sddl` is a null-terminated UTF-16 string live for the call; `descriptor` is
    // null-initialized and written by the OS, which allocates it with LocalAlloc on success.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1 as u32,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    // SAFETY: `descriptor` is the descriptor just built; `dacl` borrows from it and is used only
    // below, before the single LocalFree.
    let got = unsafe {
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
    };

    let mut wide_path = wide(&path.to_string_lossy());
    let status = if got == 0 || present == 0 {
        u32::MAX
    } else {
        // SAFETY: `wide_path` is a null-terminated UTF-16 buffer live for the call, and `dacl`
        // points into the still-live descriptor.
        unsafe {
            SetNamedSecurityInfoW(
                wide_path.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        }
    };

    // SAFETY: the exact LocalAlloc'd block the API returned; not dereferenced again.
    unsafe { LocalFree(descriptor as _) };

    if status != ERROR_SUCCESS {
        return Err(io::Error::other(format!(
            "could not set an owner-only DACL (status {status})"
        )));
    }
    Ok(())
}

/// The current process user's SID in string form, for the SDDL in [`harden_owner_only`].
#[cfg(windows)]
fn current_user_sid_string() -> io::Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: `token` is null-initialized and written by the OS on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut needed = 0u32;
    // SAFETY: a deliberate zero-length probe; the OS writes only `needed` and fails with
    // ERROR_INSUFFICIENT_BUFFER, which is the expected outcome and not an error here.
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    let mut buf = vec![0u8; needed.max(1) as usize];
    // SAFETY: `buf` is at least `needed` bytes and live for the call.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    // SAFETY: the token handle from the successful OpenProcessToken; not used again.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: on success the buffer holds a TOKEN_USER whose Sid points inside it.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut sid_str = std::ptr::null_mut();
    // SAFETY: `sid` is the valid SID above; `sid_str` is written by the OS on success.
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_str) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a null-terminated UTF-16 string the OS allocated; read fully before the free.
    let text = unsafe {
        let mut len = 0;
        while *sid_str.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, len))
    };
    // SAFETY: the exact LocalAlloc'd block returned above; not dereferenced again.
    unsafe { LocalFree(sid_str as _) };
    Ok(text)
}

/// A null-terminated UTF-16 buffer for the Win32 wide-string APIs.
#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layout under `dir` with every artifact in a writable place. The device-key directory is a
    /// SIBLING of the wallet directory, mirroring production.
    fn paths_in(dir: &Path) -> WalletPaths {
        WalletPaths {
            seed: dir.join("DigWallet").join("seed.bin"),
            device_key: dir.join("DigNode").join("device").join("device.key"),
            meta: dir.join("DigWallet").join("wallet.meta.json"),
        }
    }

    /// A path whose *existence cannot be determined*, while every other path in the layout stays
    /// perfectly writable.
    ///
    /// An interior NUL byte is rejected by the platform's own path conversion — `InvalidInput` from
    /// `CString::new` on Unix and from the UTF-16 conversion on Windows — so `try_exists` returns
    /// `Err` on both, deterministically and without needing a permission fixture that only one
    /// platform can express. It stands in for the real-world causes (permission denied, a locked
    /// file, an unmounted volume, an ACL changed by an OS update) that all arrive the same way: as
    /// an `Err` from the metadata call.
    fn unreadable_seed_path(dir: &Path) -> PathBuf {
        PathBuf::from(format!("{}\0seed.bin", dir.join("DigWallet").display()))
    }

    /// Read back the phrase actually sealed on disk, using the device key on disk. Lets a test
    /// compare wallets by identity rather than by ciphertext alone.
    fn phrase_on_disk(paths: &WalletPaths) -> String {
        let key_bytes = fs::read(&paths.device_key).expect("device key");
        let sealed = fs::read(&paths.seed).expect("seed");
        seed_store::decrypt_seed(&sealed, &hex::encode(&key_bytes))
            .expect("the seed must open under the device key on disk")
            .to_string()
    }

    /// **Proves:** a first start with no seed mints one, and a SECOND start adopts that same wallet
    /// rather than minting a different one.
    ///
    /// The phrase comparison is the real assertion — comparing ciphertext alone would also pass if
    /// the file were rewritten with an identical plaintext, and comparing nothing but the state
    /// would pass for an implementation that re-mints on every boot.
    #[test]
    fn first_start_mints_a_seed_and_a_second_start_keeps_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = paths_in(dir.path());

        assert_eq!(ensure_wallet(&paths).expect("first start"), BootstrapState::Created);
        let first = phrase_on_disk(&paths);
        assert_eq!(first.split_whitespace().count(), MNEMONIC_WORDS);

        assert_eq!(ensure_wallet(&paths).expect("second start"), BootstrapState::Opened);
        assert_eq!(
            phrase_on_disk(&paths),
            first,
            "a second start must not replace the wallet the first one created"
        );
    }

    /// **Proves:** an unreadable seed path is treated as UNKNOWN, not as absent.
    ///
    /// This is the assertion that stands between a transient I/O error and an overwritten wallet.
    /// `Path::exists()` answers `false` here; `presence` must answer `Err`.
    #[test]
    fn an_unreadable_seed_path_is_an_error_not_an_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = unreadable_seed_path(dir.path());

        // The fixture is only meaningful if the platform really does fail this metadata call, and
        // if the naive predicate really does answer "absent" — pin both, so the test cannot quietly
        // stop testing anything.
        assert!(!path.exists(), "Path::exists() reports absence for this path");
        assert!(
            presence(&path).is_err(),
            "an unanswerable existence question must surface as Err, never as Absent"
        );
    }

    /// **Proves:** when the seed path cannot be read, the bootstrap writes NOTHING — not the seed,
    /// and not the device key either.
    ///
    /// The fixture is built so the two answers differ: only the seed path is unreadable, while the
    /// device-key directory is an ordinary writable temp directory. An implementation that asks
    /// `exists()` gets `false`, concludes the wallet is absent, and mints a device key into that
    /// perfectly good directory — leaving an artifact this test can see. Assert on the artifact
    /// rather than only on the returned error, because the error is also what a correct
    /// implementation returns *after* having already written one.
    #[test]
    fn an_unreadable_seed_path_produces_no_write_at_all() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut paths = paths_in(dir.path());
        paths.seed = unreadable_seed_path(dir.path());

        let outcome = ensure_wallet(&paths);

        assert!(
            matches!(outcome, Err(BootstrapError::SeedPathUnreadable(_))),
            "must fail closed on an unreadable seed path, got {outcome:?}"
        );
        assert!(
            !paths.device_key.exists(),
            "no device key may be minted when the seed's presence is unknown"
        );
        assert!(
            !paths.meta.exists(),
            "no metadata may be written when the seed's presence is unknown"
        );
    }

    /// **Proves:** a seed that exists but does not open under the device key is left byte-identical.
    ///
    /// The fixture is a wallet sealed under a USER password — the ordinary imported wallet, and the
    /// most valuable thing on the disk. To the bootstrap it is indistinguishable from a corrupt
    /// file or a mismatched key, which is exactly why the rule is "leave it alone" rather than
    /// "work out which".
    #[test]
    fn a_seed_that_does_not_decrypt_is_left_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = paths_in(dir.path());
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon art";

        let users_wallet = seed_store::encrypt_seed(PHRASE, "the-users-own-password").expect("seal");
        fs::create_dir_all(paths.seed.parent().unwrap()).expect("wallet dir");
        fs::write(&paths.seed, &users_wallet).expect("write the user's wallet");
        write_new_owner_only(&paths.device_key, &[7u8; DEVICE_KEY_LEN]).expect("device key");

        assert_eq!(ensure_wallet(&paths).expect("bootstrap"), BootstrapState::Locked);
        assert_eq!(
            fs::read(&paths.seed).expect("seed still there"),
            users_wallet,
            "a seed that fails to decrypt is still evidence of a wallet and must not be rewritten"
        );
    }

    /// **Proves:** a seed with no device key is reported as `Orphaned` and NO new device key is
    /// minted.
    ///
    /// Minting one here would be silent, permanent loss: the fresh key cannot open the existing
    /// seed, so the node would come up presenting an empty wallet as though it were the user's. The
    /// state is recoverable — a wrong mount, a half-restored backup, a container missing a volume —
    /// but only for as long as nothing overwrites it.
    #[test]
    fn a_seed_without_its_device_key_is_orphaned_and_mints_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = paths_in(dir.path());
        fs::create_dir_all(paths.seed.parent().unwrap()).expect("wallet dir");
        fs::write(&paths.seed, b"DIGOP1 sealed under a device key that is gone").expect("seed");

        assert_eq!(ensure_wallet(&paths).expect("bootstrap"), BootstrapState::Orphaned);
        assert!(
            !paths.device_key.exists(),
            "a device key must never be minted beside a seed it cannot open"
        );
    }

    /// **Proves:** a freshly minted wallet is marked `auto` and is disposable, and that the created
    /// timestamp is recorded.
    #[test]
    fn a_minted_wallet_is_marked_auto_and_disposable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = paths_in(dir.path());
        ensure_wallet(&paths).expect("bootstrap");

        let meta = read_meta(&paths.meta).expect("the sidecar is written on creation");
        assert_eq!(meta.origin, SeedOrigin::Auto);
        assert!(!meta.ever_funded);
        assert!(meta.is_disposable());
        assert!(is_disposable(&paths));
        assert!(
            meta.created_at.contains('T'),
            "created_at is RFC 3339: {}",
            meta.created_at
        );
    }

    /// **Proves:** the funded latch is monotonic and outranks the origin — once a wallet has held
    /// money, no surface may call it disposable, whatever its balance reads later.
    #[test]
    fn the_funded_latch_ends_disposability_permanently() {
        let mut meta = WalletMeta {
            origin: SeedOrigin::Auto,
            created_at: "2026-08-20T00:00:00Z".to_string(),
            ever_funded: false,
        };
        assert!(meta.is_disposable());

        meta.mark_ever_funded();
        assert!(!meta.is_disposable());

        // A later balance read of zero is not evidence the wallet never mattered, and there is no
        // API that could express it: the latch has no clearing path.
        meta.mark_ever_funded();
        assert!(!meta.is_disposable());
    }

    /// **Proves:** an absent or unparsable sidecar answers "not disposable".
    ///
    /// An existing seed with no readable metadata is far more likely to be an imported wallet that
    /// predates the sidecar than a minted one, and the expensive direction of that guess is the one
    /// that offers to discard someone's funds.
    #[test]
    fn an_unreadable_sidecar_is_never_disposable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = paths_in(dir.path());
        assert!(!is_disposable(&paths), "absent sidecar");

        fs::create_dir_all(paths.meta.parent().unwrap()).expect("dir");
        fs::write(&paths.meta, b"{ not json").expect("write");
        assert!(!is_disposable(&paths), "unparsable sidecar");
    }

    /// **Proves:** an acknowledged wallet stops being disposable, so the back-up nudge can end.
    #[test]
    fn acknowledging_the_phrase_ends_disposability() {
        let meta = WalletMeta {
            origin: SeedOrigin::AutoAcknowledged,
            created_at: "2026-08-20T00:00:00Z".to_string(),
            ever_funded: false,
        };
        assert!(!meta.is_disposable());
    }

    /// **Proves:** the device key and the seed do not share a directory.
    ///
    /// The separation IS the partial-exfiltration boundary — a backup rule that captures the wallet
    /// directory must not capture the key that opens it. Pinned as a test because the two paths are
    /// always used together, which makes merging them look like a tidy-up rather than like the
    /// removal of the only property this design buys.
    #[test]
    fn the_device_key_never_shares_the_wallet_directory() {
        let paths = WalletPaths::resolve(PathBuf::from("/base/DigWallet/seed.bin"));
        let wallet_dir = paths.seed.parent().expect("wallet dir");
        let key_dir = paths.device_key.parent().expect("device dir");

        assert_ne!(wallet_dir, key_dir);
        assert!(
            !key_dir.starts_with(wallet_dir),
            "the device key must not live under the wallet directory: {} is inside {}",
            key_dir.display(),
            wallet_dir.display()
        );
        assert_eq!(paths.meta.parent(), Some(wallet_dir));
    }

    /// **Proves:** two concurrent starts converge on ONE wallet — the loser adopts the winner's
    /// seed instead of overwriting it.
    ///
    /// Simulated at the write layer rather than with threads so the assertion is deterministic:
    /// `create_new` is the atomic test-and-set the whole race argument rests on, and this pins that
    /// it really refuses the second write.
    #[test]
    fn a_racing_start_adopts_the_winner_rather_than_clobbering_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = paths_in(dir.path());
        ensure_wallet(&paths).expect("the winning start");
        let winners_phrase = phrase_on_disk(&paths);

        let loser = write_new_owner_only(&paths.seed, b"a second start's seed");
        assert_eq!(
            loser.expect_err("the second write must be refused").kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(phrase_on_disk(&paths), winners_phrase);
    }

    /// **Proves:** a device key of the wrong length is refused rather than stretched or truncated
    /// into a key that would silently open nothing.
    #[test]
    fn a_malformed_device_key_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = paths_in(dir.path());
        write_new_owner_only(&paths.device_key, b"too short").expect("write");

        assert!(matches!(
            load_device_key(&paths.device_key, false),
            Err(DeviceKeyError::Malformed)
        ));
    }

    /// **Proves:** on Windows the secrets carry an EXPLICIT owner-only DACL — exactly one ACE,
    /// granting exactly this user — rather than whatever the parent directory happened to hand
    /// down.
    ///
    /// Written because the Unix `0600` test below cannot run on Windows, which would otherwise
    /// leave the file-permission property of the whole design asserted by nothing on the platform
    /// most of these nodes run on. The ACE count is the load-bearing half: an inherited ACL brings
    /// several ACEs (SYSTEM and Administrators among them), so a single ACE is only possible if
    /// `PROTECTED_DACL_SECURITY_INFORMATION` really did sever inheritance.
    #[cfg(windows)]
    #[test]
    fn secrets_are_created_with_an_explicit_owner_only_dacl() {
        use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
        use windows_sys::Win32::Security::Authorization::{
            GetNamedSecurityInfoW, SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::{GetAce, ACL, DACL_SECURITY_INFORMATION};

        let dir = tempfile::tempdir().expect("tempdir");
        let paths = paths_in(dir.path());
        ensure_wallet(&paths).expect("bootstrap");
        let me = current_user_sid_string().expect("current user sid");

        for path in [&paths.seed, &paths.device_key, &paths.meta] {
            let wide_path = wide(&path.to_string_lossy());
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            // SAFETY: `wide_path` is a live null-terminated UTF-16 string; the out-params are
            // null-initialized and written by the OS, which owns the descriptor until LocalFree.
            let status = unsafe {
                GetNamedSecurityInfoW(
                    wide_path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut dacl,
                    std::ptr::null_mut(),
                    &mut descriptor,
                )
            };
            assert_eq!(status, ERROR_SUCCESS, "read the DACL of {}", path.display());

            // SAFETY: on ERROR_SUCCESS the DACL points into the live descriptor.
            let count = unsafe { (*dacl).AceCount };
            assert_eq!(
                count,
                1,
                "{} must carry exactly one ACE — more means inheritance was not severed",
                path.display()
            );

            let mut ace = std::ptr::null_mut();
            // SAFETY: index 0 exists given the AceCount assertion above.
            let got = unsafe { GetAce(dacl, 0, &mut ace) };
            assert_ne!(got, 0, "read the single ACE of {}", path.display());
            // SAFETY: an allowed ACE's SID begins at the fixed SidStart offset of the standard
            // (non-object) ACE layout — 8 bytes past the header.
            let sid = unsafe { ace.cast::<u8>().add(8).cast() };
            // SAFETY: `sid` is that ACE's SID, live until the free below.
            let granted = unsafe { sid_to_string(sid) }.expect("render the ACE's SID");

            // SAFETY: the exact LocalAlloc'd block the API returned; not dereferenced again.
            unsafe { LocalFree(descriptor as _) };

            assert_eq!(
                granted,
                me,
                "{} must grant only this user",
                path.display()
            );
        }
    }

    /// Render a SID as its string form, for the DACL assertion above.
    ///
    /// # Safety
    /// `sid` must point at a valid SID that outlives the call.
    #[cfg(windows)]
    unsafe fn sid_to_string(sid: *mut std::ffi::c_void) -> Option<String> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

        let mut text = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut text) == 0 {
            return None;
        }
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text as _);
        Some(s)
    }

    /// **Proves:** a secret file is created owner-only, not merely moved there afterwards.
    #[cfg(unix)]
    #[test]
    fn secrets_are_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = paths_in(dir.path());
        ensure_wallet(&paths).expect("bootstrap");

        for path in [&paths.seed, &paths.device_key] {
            let mode = fs::metadata(path).expect("metadata").permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "{} must be owner-only (got {mode:o})",
                path.display()
            );
        }
    }
}
