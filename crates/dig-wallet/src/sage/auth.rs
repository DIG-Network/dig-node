//! Node-managed unlock authentication + per-transaction sign-unlock (#431/#432, SPEC §18.24).
//!
//! The node is the LOCAL authority (no central server) that gates the node-custodied signer
//! (§18.21). This module owns the auth+unlock STATE MACHINE that makes signing SAFE BY DEFAULT: the
//! decrypted private key MUST NOT persist in memory beyond a single signature.
//!
//! # The guarantee
//!
//! A successful [`unlock`](UnlockAuth::unlock) grants a READ-ONLY session (balances/history/reads)
//! and loads NO signer; **each signing operation requires a fresh [`sign_unlock`](UnlockAuth::sign_unlock)**
//! that decrypts the seed, builds a ONE-SHOT signer bound to that wallet, signs exactly one operation,
//! and drops it (the key is not resident between signatures). The `session_unlock_all` mode
//! ([`UnlockMode`]) is the OPT-OUT convenience where one unlock holds the signer for the session; it
//! is OFF by default and switching INTO it re-verifies the current factor.
//!
//! # Auth model (per #431/#432, revised by the #432 adversarial review)
//!
//! - The **password is per-wallet** — it is the at-rest KDF root that decrypts THAT wallet's seed
//!   (`dig-keystore` Argon2id, §18.18/§18.20). Every unlock/sign-unlock needs the target wallet's
//!   password.
//! - The **second factor (TOTP / passkey) is NODE-LEVEL** — a single node authentication that
//!   authorizes the unlock across every wallet (#431). Its secret is sealed at rest under a
//!   node-level device key (`auth/node.key`, owner-only), NOT under any wallet password, so 2FA works
//!   uniformly for all custodied wallets. When a second factor is enrolled, `unlock`/`sign_unlock`
//!   require BOTH the target wallet's password AND the node-level factor.
//! - **Enrolling or replacing a factor re-verifies the CURRENT factor** (not just the password), so an
//!   attacker holding the paired token + a stolen password — the exact threat 2FA backstops — cannot
//!   rotate the factor to their own authenticator.
//! - **TOTP is one-time-use** (RFC-6238 §5.2): the last-accepted time-step is persisted and a code at a
//!   step `<=` it is rejected as a replay.
//! - **Passkey/WebAuthn** is behind the same interface; the real `webauthn-rs` ceremony is finalized
//!   with the extension origin (#433 follow-up) — it fails closed until then, so the active method
//!   never becomes `passkey` on this node.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use dig_keystore::{opaque, KdfParams, Password};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use super::custody::WalletCustody;
use super::spend::WalletSigner;
use super::{Error, Result};

/// The unlock mode — the ONLY policy knob (§18.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnlockMode {
    /// DEFAULT (secure): an unlock grants a READ-ONLY session; each signature needs a fresh
    /// `sign_unlock` → decrypt → sign one → drop. The key is never resident between signatures.
    #[default]
    PerTransaction,
    /// OPT-OUT (convenience, OFF by default): one unlock holds the signer for the session lifetime.
    SessionUnlockAll,
}

/// The active unlock authentication method (§18.24). One is active at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Password only (the default). The password is the wallet seed's at-rest KDF root.
    #[default]
    Password,
    /// Password + a node-level RFC-6238 TOTP code (2FA).
    Totp,
    /// Password + a node-level WebAuthn assertion. Ceremony finalized with the extension origin (#433).
    Passkey,
}

/// The reported session state (§18.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSessionState {
    /// No active session: no reads authorized, no signer available.
    Locked,
    /// A read-only session is active (reads authorized); signing still needs a `sign_unlock`
    /// (per-transaction) or is enabled via the held session signer (session-unlock-all).
    ReadOnly,
}

/// A presented unlock credential (§18.24). The password is always required (it decrypts the target
/// wallet's seed); the active method dictates which additional NODE-LEVEL factor must also be present.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Credential {
    /// The target wallet's password (its seed's at-rest KDF root). Always required.
    #[serde(default)]
    pub password: String,
    /// The current node-level TOTP code — required when the active method is [`AuthMethod::Totp`].
    #[serde(default)]
    pub totp_code: Option<String>,
    /// The node-level WebAuthn assertion — required when the active method is [`AuthMethod::Passkey`] (#433).
    #[serde(default)]
    pub passkey_assertion: Option<serde_json::Value>,
}

impl Credential {
    /// A password-only credential (test/convenience helper).
    pub fn password(pw: impl Into<String>) -> Self {
        Self {
            password: pw.into(),
            totp_code: None,
            passkey_assertion: None,
        }
    }
    /// A password + TOTP-code credential.
    pub fn with_totp(pw: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            password: pw.into(),
            totp_code: Some(code.into()),
            passkey_assertion: None,
        }
    }
}

/// The one-time TOTP enrollment result (§18.24). Returned ONLY at `enroll_totp` — the caller needs
/// the secret/URI to provision the authenticator (QR). Never re-derivable afterwards.
#[derive(Debug, Clone, Serialize)]
pub struct TotpEnrollment {
    /// The base32-encoded shared secret (the authenticator's manual-entry key).
    pub secret_base32: String,
    /// The `otpauth://totp/...` provisioning URI (rendered as a QR by the caller).
    pub otpauth_uri: String,
}

/// A registered passkey credential (non-secret: id + public key + signature counter). (#433.)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PasskeyCredential {
    /// The credential id (base64url).
    pub id: String,
    /// The credential public key (COSE/base64url).
    pub public_key: String,
    /// The last-seen signature counter (monotonic anti-clone check).
    pub counter: u32,
}

/// The auth status reported by [`UnlockAuth::status`] (§18.24) / `auth.status`.
#[derive(Debug, Clone, Serialize)]
pub struct AuthStatus {
    /// The active unlock mode.
    pub mode: UnlockMode,
    /// The active authentication method.
    pub method: AuthMethod,
    /// The current session state.
    pub state: AuthSessionState,
    /// Whether a one-shot per-transaction sign grant is armed right now.
    pub sign_armed: bool,
    /// Whether any wallet is custodied on this node (so a caller knows unlock is possible).
    pub has_wallet: bool,
}

/// The persisted, NON-SECRET auth config (`<config_dir>/auth/config.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AuthConfig {
    #[serde(default)]
    mode: UnlockMode,
    #[serde(default)]
    method: AuthMethod,
    /// The registered passkey credential, when the method is `passkey` (non-secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passkey: Option<PasskeyCredential>,
    /// The last-accepted TOTP time-step (RFC-6238 §5.2 one-time-use, #432 Finding B). A code at a
    /// step `<=` this is rejected as a replay. Persisted so replay protection survives a restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    totp_last_step: Option<u64>,
}

/// A signer bound to the wallet it was decrypted for (#432 Decision 8): the effective-signer gate
/// only returns it when the op's ACTIVE wallet matches, so a grant/session can never sign for the
/// wrong wallet (multi-wallet, #427).
type BoundSigner = (String, Arc<WalletSigner>);

/// The runtime (non-persisted) unlock state.
#[derive(Default)]
struct Runtime {
    /// Whether a read-only session is active.
    read_only: bool,
    /// The held session signer (session-unlock-all mode only), bound to its wallet id.
    session_signer: Option<BoundSigner>,
    /// The armed one-shot per-transaction sign grant, bound to its wallet id (consumed after one op).
    sign_grant: Option<BoundSigner>,
}

/// The subdirectory (under the node config dir) holding the auth config + sealed secrets.
const AUTH_SUBDIR: &str = "auth";
/// The non-secret auth config filename.
const CONFIG_FILE: &str = "config.json";
/// The sealed-TOTP-secret filename (a `dig-keystore` container, sealed under the NODE-level key).
const TOTP_FILE: &str = "totp.dig";
/// The node-level device key filename (owner-only) that seals the node-level 2nd-factor secret.
const NODE_KEY_FILE: &str = "node.key";
/// Fixed TOTP parameters (RFC-6238 defaults, matching common authenticators).
const TOTP_ISSUER: &str = "DIG Node";
const TOTP_DIGITS: usize = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP: u64 = 30;

/// The node-managed unlock authority (§18.24). Owns the auth+unlock state machine over a
/// [`WalletCustody`] (§18.20). Cheap to `clone` — all state is shared behind `Arc`s, so an
/// `unlock`/`sign_unlock`/`lock` on one handle is visible on the others.
#[derive(Clone)]
pub struct UnlockAuth {
    /// The node-custodied wallets this authority gates.
    custody: WalletCustody,
    /// The node config directory (holds `auth/`).
    config_dir: PathBuf,
    /// The persisted, non-secret config (mode + method + passkey credential + TOTP replay counter).
    config: Arc<RwLock<AuthConfig>>,
    /// The runtime unlock state (read-only flag + session/one-shot signers).
    runtime: Arc<RwLock<Runtime>>,
}

impl UnlockAuth {
    /// Build the unlock authority over `custody`, rooted at `config_dir`. Loads the on-disk auth
    /// config (or the secure defaults: `per_transaction` + `password`) — signing starts LOCKED
    /// regardless of prior state (the runtime session is never persisted).
    pub fn new(custody: WalletCustody, config_dir: PathBuf) -> Self {
        let config = Self::read_config(&config_dir).unwrap_or_default();
        Self {
            custody,
            config_dir,
            config: Arc::new(RwLock::new(config)),
            runtime: Arc::new(RwLock::new(Runtime::default())),
        }
    }

    // ---- policy (mode + method) ------------------------------------------

    /// The active unlock mode.
    pub fn mode(&self) -> UnlockMode {
        self.config.read().unwrap().mode
    }

    /// Set the unlock mode (§18.24, #432 Finding 3). Switching INTO `session_unlock_all` WEAKENS the
    /// posture (the next unlock loads a session-resident signer), so it REQUIRES a valid current-factor
    /// `cred` — a paired token alone must not silently downgrade. Switching to `per_transaction`
    /// (tightening) needs no credential and immediately drops any held session signer.
    pub fn set_mode(&self, id: Option<&str>, mode: UnlockMode, cred: &Credential) -> Result<()> {
        if mode == UnlockMode::SessionUnlockAll {
            self.verify(id, cred)?;
        }
        {
            let mut c = self.config.write().unwrap();
            c.mode = mode;
        }
        if mode == UnlockMode::PerTransaction {
            self.runtime.write().unwrap().session_signer = None;
        }
        self.persist_config()
    }

    /// The active authentication method.
    pub fn method(&self) -> AuthMethod {
        self.config.read().unwrap().method
    }

    /// The current auth status (§18.24).
    pub fn status(&self) -> AuthStatus {
        let cfg = self.config.read().unwrap();
        let rt = self.runtime.read().unwrap();
        AuthStatus {
            mode: cfg.mode,
            method: cfg.method,
            state: if rt.read_only {
                AuthSessionState::ReadOnly
            } else {
                AuthSessionState::Locked
            },
            sign_armed: rt.sign_grant.is_some(),
            has_wallet: self.custody.any_wallet(),
        }
    }

    // ---- enrollment ------------------------------------------------------

    /// Enroll (or rotate) TOTP as the active NODE-LEVEL method (§18.24, #432 Findings A + Decision 9).
    ///
    /// Re-verifies the CURRENT factor via `self.verify(id, cred)` FIRST — so when a second factor is
    /// already active, the live code is required (an attacker with only the paired token + password
    /// cannot re-enroll their own authenticator). Then generates a fresh secret, seals it under the
    /// node-level device key (NOT any wallet password), sets the method to `totp`, resets the replay
    /// counter, and returns the base32 secret + `otpauth://` URI ONCE. Fails closed on a bad credential.
    pub fn enroll_totp(&self, id: Option<&str>, cred: &Credential) -> Result<TotpEnrollment> {
        // Re-verify the current factor before rotating (Finding A). Password-only enroll is allowed
        // ONLY when the method is currently Password (verify then checks just the password).
        self.verify(id, cred)?;
        let node_key = self.ensure_node_key()?;
        let secret = Secret::generate_secret();
        let secret_bytes = secret
            .to_bytes()
            .map_err(|e| Error::internal(format!("totp secret: {e}")))?;
        let totp = Self::build_totp(secret_bytes.clone())?;
        // Seal the secret under the NODE-level key (node-level 2nd factor, Decision 9).
        let sealed = opaque::seal(
            &Password::from(hex::encode(&node_key)),
            &secret_bytes,
            KdfParams::default(),
        )
        .map_err(|e| Error::internal(format!("seal totp secret: {e}")))?;
        std::fs::write(self.totp_path(), &sealed)
            .map_err(|e| Error::internal(format!("write totp secret: {e}")))?;
        restrict_permissions(&self.totp_path());
        {
            let mut c = self.config.write().unwrap();
            c.method = AuthMethod::Totp;
            c.passkey = None;
            c.totp_last_step = None; // fresh secret ⇒ fresh replay window
        }
        self.persist_config()?;
        Ok(TotpEnrollment {
            secret_base32: totp.get_secret_base32(),
            otpauth_uri: totp.get_url(),
        })
    }

    /// Disable any second factor and return to `password`-only (§18.24): re-verify the CURRENT
    /// factor's `cred`, then remove the TOTP/passkey material and set the method to `password`.
    pub fn set_method_password(&self, id: Option<&str>, cred: &Credential) -> Result<()> {
        self.verify(id, cred)?;
        let _ = std::fs::remove_file(self.totp_path());
        {
            let mut c = self.config.write().unwrap();
            c.method = AuthMethod::Password;
            c.passkey = None;
            c.totp_last_step = None;
        }
        self.persist_config()
    }

    /// Begin a passkey (WebAuthn) registration (§18.24). Re-verifies the current factor, but the real
    /// `webauthn-rs` ceremony is finalized with the extension origin (#433): it fails closed here so
    /// the method never becomes `passkey` until that lands.
    pub fn enroll_passkey_begin(
        &self,
        id: Option<&str>,
        cred: &Credential,
    ) -> Result<serde_json::Value> {
        self.verify(id, cred)?;
        Err(Self::passkey_deferred())
    }

    /// Finish a passkey registration (see [`Self::enroll_passkey_begin`]) — deferred to #433.
    pub fn enroll_passkey_finish(&self, _response: &serde_json::Value) -> Result<()> {
        Err(Self::passkey_deferred())
    }

    // ---- the unlock state machine ----------------------------------------

    /// Authenticate to the node and grant a READ-ONLY session (§18.24). Verifies `cred` per the active
    /// method; on success sets the session read-only and — in `session_unlock_all` mode ONLY — builds
    /// and HOLDS the signer for the session (bound to its wallet). In the DEFAULT `per_transaction`
    /// mode NO signer is loaded. A wrong/expired/replayed credential is denied (`401`), leaves the
    /// state unchanged, and loads nothing.
    pub fn unlock(&self, id: Option<&str>, cred: &Credential) -> Result<AuthStatus> {
        self.verify(id, cred)?;
        let mode = self.mode();
        // Build the session signer BEFORE taking the runtime lock (I/O + key derivation).
        let session_signer = if mode == UnlockMode::SessionUnlockAll {
            Some(self.build_bound_signer(id, &cred.password)?)
        } else {
            None
        };
        {
            let mut rt = self.runtime.write().unwrap();
            rt.read_only = true;
            rt.session_signer = session_signer;
            rt.sign_grant = None;
        }
        Ok(self.status())
    }

    /// Authorize exactly ONE signing operation (§18.24). Verifies `cred` FRESH per the active method,
    /// decrypts the target wallet's seed, and arms a ONE-SHOT signer BOUND to that wallet
    /// ([`Self::consume_sign_grant`] drops it after one op). Required for every signature in the
    /// DEFAULT `per_transaction` mode. A wrong/expired/replayed credential is denied (`401`) and arms
    /// nothing.
    pub fn sign_unlock(&self, id: Option<&str>, cred: &Credential) -> Result<AuthStatus> {
        self.verify(id, cred)?;
        let grant = self.build_bound_signer(id, &cred.password)?;
        {
            let mut rt = self.runtime.write().unwrap();
            rt.read_only = true;
            rt.sign_grant = Some(grant);
        }
        Ok(self.status())
    }

    /// Lock: clear the read-only session and DROP both the session signer and any armed one-shot
    /// grant, releasing the decrypted-key allocation. Idempotent.
    pub fn lock(&self) {
        let mut rt = self.runtime.write().unwrap();
        rt.read_only = false;
        rt.session_signer = None;
        rt.sign_grant = None;
    }

    /// The EFFECTIVE signer the §18.21 sign path obtains (the auth gate, #432 Decision 8). Returns the
    /// armed one-shot grant if present (per-transaction), else the held session signer
    /// (session-unlock-all) — but ONLY when the bound wallet matches the node's CURRENTLY-ACTIVE
    /// wallet. A grant/session bound to a different wallet than the op targets fails closed (`None`),
    /// so a signature can never be produced for the wrong wallet. Reading it does NOT consume the
    /// one-shot grant.
    pub fn effective_signer(&self) -> Option<Arc<WalletSigner>> {
        // The Sage sign path (§18.21) signs with the ACTIVE wallet; the grant/session must be bound to
        // that same wallet.
        let active = self.custody.status(None).id?;
        let rt = self.runtime.read().unwrap();
        if let Some((wid, sig)) = &rt.sign_grant {
            // An armed grant is authoritative: it must match the active wallet, else fail closed
            // (never fall back to a session signer while a grant is armed for a different wallet).
            return (*wid == active).then(|| sig.clone());
        }
        if let Some((wid, sig)) = &rt.session_signer {
            if *wid == active {
                return Some(sig.clone());
            }
        }
        None
    }

    /// Consume the one-shot per-transaction sign grant after a single signing operation (§18.24): drop
    /// it so the decrypted-key allocation is released and the NEXT signature requires a fresh
    /// `sign_unlock`. A no-op when nothing is armed. Panic-safe consumption is enforced by the
    /// caller's RAII guard (rpc dispatch).
    pub fn consume_sign_grant(&self) {
        self.runtime.write().unwrap().sign_grant = None;
    }

    // ---- verification ----------------------------------------------------

    /// Verify a presented credential against the active method (§18.24). The target wallet's password
    /// is ALWAYS checked (per-wallet KDF root); the node-level factor is then required per the active
    /// method. Fails closed on any missing/wrong/replayed factor. NEVER mutates unlock state (it MAY
    /// advance the persisted TOTP replay counter — a successful code is one-time-use).
    fn verify(&self, id: Option<&str>, cred: &Credential) -> Result<()> {
        self.custody.verify_password(id, &cred.password)?;
        match self.method() {
            AuthMethod::Password => Ok(()),
            AuthMethod::Totp => self.verify_totp(cred.totp_code.as_deref()),
            AuthMethod::Passkey => self.verify_passkey(cred.passkey_assertion.as_ref()),
        }
    }

    /// Verify a node-level TOTP code with RFC-6238 one-time-use (#432 Finding B + re-verify).
    ///
    /// Opens the node-level secret with the device key, finds the time-step (within ±1) whose code
    /// matches, and REJECTS it if that step is `<=` the last-accepted step (a replay). The
    /// find → compare-to-`last` → advance-`last` sequence is done ATOMICALLY under a SINGLE
    /// `config.write()` guard (an exclusive lock, so no two verifies can both read `last` before either
    /// advances it) — since `auth.*` dispatch is NOT otherwise serialized, a non-atomic read-then-write
    /// would re-open the in-process replay window under concurrency. The disk persist happens AFTER the
    /// guard is released (best-effort durability across restart); the authoritative one-time-use gate is
    /// the in-memory monotonic advance under the exclusive lock.
    fn verify_totp(&self, code: Option<&str>) -> Result<()> {
        let code = code.ok_or_else(|| Error::unauthorized("a TOTP code is required"))?;
        let node_key = std::fs::read(self.node_key_path())
            .map_err(|_| Error::internal("TOTP is not enrolled on this node"))?;
        let bytes = std::fs::read(self.totp_path())
            .map_err(|_| Error::internal("TOTP is not enrolled on this node"))?;
        let secret = opaque::open(&Password::from(hex::encode(&node_key)), &bytes)
            .map_err(|_| Error::internal("could not open the TOTP secret"))?;
        let totp = Self::build_totp(secret.to_vec())?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cur = now / TOTP_STEP;

        // ATOMIC check-and-advance: the whole find → compare → advance runs under ONE exclusive write
        // guard, so two concurrent verifies of the SAME code cannot both pass `step <= last`.
        {
            let mut cfg = self.config.write().unwrap();
            let last = cfg.totp_last_step;
            // Check the skew window newest-first so the highest matching step wins.
            let matched = [cur + 1, cur, cur.saturating_sub(1)]
                .into_iter()
                .find(|&step| totp.generate(step * TOTP_STEP) == code);
            match matched {
                None => return Err(Error::unauthorized("invalid or expired TOTP code")),
                Some(step) if last.is_some_and(|l| step <= l) => {
                    return Err(Error::unauthorized("TOTP code already used (replay)"))
                }
                Some(step) => cfg.totp_last_step = Some(step),
            }
            // `cfg` (the exclusive guard) drops here.
        }
        // Persist AFTER releasing the guard — the in-memory advance above already closed the window;
        // this only makes the counter durable across a restart. NB: `persist_config` re-locks the
        // config, so it MUST NOT run while the write guard is held (that would deadlock).
        self.persist_config()
    }

    /// Verify a WebAuthn assertion — deferred to #433 (fails closed).
    fn verify_passkey(&self, _assertion: Option<&serde_json::Value>) -> Result<()> {
        Err(Self::passkey_deferred())
    }

    // ---- helpers ---------------------------------------------------------

    /// Build a signer for the addressed wallet (default: active) bound to its RESOLVED id (#432
    /// Decision 8), decrypting the seed with `password`. The signer is not persisted into custody.
    fn build_bound_signer(&self, id: Option<&str>, password: &str) -> Result<BoundSigner> {
        let wallet_id = self
            .custody
            .status(id)
            .id
            .ok_or_else(|| Error::not_found("no wallet on this device"))?;
        let signer = self.custody.sign_once(id, password)?;
        Ok((wallet_id, signer))
    }

    /// Read the node-level device key, creating it (owner-only, random) on first use.
    fn ensure_node_key(&self) -> Result<Vec<u8>> {
        std::fs::create_dir_all(self.auth_dir())
            .map_err(|e| Error::internal(format!("create auth dir: {e}")))?;
        let path = self.node_key_path();
        if let Ok(k) = std::fs::read(&path) {
            if !k.is_empty() {
                return Ok(k);
            }
        }
        // 20 random bytes (160-bit) from the same CSPRNG totp-rs uses — ample for a device key.
        let key = Secret::generate_secret()
            .to_bytes()
            .map_err(|e| Error::internal(format!("node key: {e}")))?;
        std::fs::write(&path, &key).map_err(|e| Error::internal(format!("write node key: {e}")))?;
        restrict_permissions(&path);
        Ok(key)
    }

    /// Build a [`TOTP`] over `secret` with the fixed DIG parameters (SHA1/6-digit/30s/±1).
    fn build_totp(secret: Vec<u8>) -> Result<TOTP> {
        TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret,
            Some(TOTP_ISSUER.to_string()),
            "dig-node".to_string(),
        )
        .map_err(|e| Error::internal(format!("build totp: {e}")))
    }

    /// The stable "passkey ceremony is finalized in #433" error (fails closed).
    fn passkey_deferred() -> Error {
        Error::api(
            "passkey (WebAuthn) enrollment is finalized with the paired-extension origin (see #433); \
             use password or TOTP until then",
        )
    }

    /// The `auth/` directory under the node config dir.
    fn auth_dir(&self) -> PathBuf {
        self.config_dir.join(AUTH_SUBDIR)
    }
    /// The auth config path (`auth/config.json`).
    fn config_path(&self) -> PathBuf {
        self.auth_dir().join(CONFIG_FILE)
    }
    /// The sealed-TOTP-secret path (`auth/totp.dig`).
    fn totp_path(&self) -> PathBuf {
        self.auth_dir().join(TOTP_FILE)
    }
    /// The node-level device-key path (`auth/node.key`).
    fn node_key_path(&self) -> PathBuf {
        self.auth_dir().join(NODE_KEY_FILE)
    }

    /// Read the on-disk auth config, or `None` when absent/unreadable/corrupt (the caller defaults).
    fn read_config(config_dir: &std::path::Path) -> Option<AuthConfig> {
        let bytes = std::fs::read(config_dir.join(AUTH_SUBDIR).join(CONFIG_FILE)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Persist the (non-secret) auth config atomically + owner-only.
    fn persist_config(&self) -> Result<()> {
        let dir = self.auth_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::internal(format!("create auth dir: {e}")))?;
        let json = {
            let c = self.config.read().unwrap();
            serde_json::to_vec_pretty(&*c)
                .map_err(|e| Error::internal(format!("serialize auth config: {e}")))?
        };
        let path = self.config_path();
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| Error::internal(format!("write auth config: {e}")))?;
        restrict_permissions(&tmp);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            Error::internal(format!("persist auth config: {e}"))
        })?;
        Ok(())
    }
}

/// Restrict a file to owner read/write on Unix (`0600`); best-effort. No-op on non-Unix.
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) {}

#[cfg(test)]
mod tests {
    use super::super::custody::Network;
    use super::*;

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";
    /// A second, distinct known mnemonic (different fingerprint) for multi-wallet tests.
    const LEGAL: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const PW: &str = "correcthorse";

    /// A fresh authority over a custody manager with ONE imported (locked) wallet.
    fn fresh() -> (UnlockAuth, WalletCustody, PathBuf) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("dig-node-auth-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        let custody = WalletCustody::new(dir.clone(), Network::Mainnet, 3);
        custody.import(ABANDON, PW, None).unwrap();
        custody.lock(None);
        (UnlockAuth::new(custody.clone(), dir.clone()), custody, dir)
    }

    /// Generate the CURRENT live TOTP code for an enrolled authority (reads the returned secret).
    fn live_code(enroll: &TotpEnrollment) -> String {
        let secret = Secret::Encoded(enroll.secret_base32.clone())
            .to_bytes()
            .unwrap();
        UnlockAuth::build_totp(secret)
            .unwrap()
            .generate_current()
            .unwrap()
    }

    #[test]
    fn defaults_are_secure_per_transaction_password_locked() {
        let (a, _c, _d) = fresh();
        let s = a.status();
        assert_eq!(s.mode, UnlockMode::PerTransaction);
        assert_eq!(s.method, AuthMethod::Password);
        assert_eq!(s.state, AuthSessionState::Locked);
        assert!(!s.sign_armed);
        assert!(s.has_wallet);
        assert!(a.effective_signer().is_none());
    }

    #[test]
    fn read_only_unlock_grants_reads_but_no_signer() {
        let (a, _c, _d) = fresh();
        let s = a.unlock(None, &Credential::password(PW)).unwrap();
        assert_eq!(s.state, AuthSessionState::ReadOnly);
        assert!(a.effective_signer().is_none());
    }

    #[test]
    fn per_transaction_requires_fresh_sign_unlock_per_signature() {
        let (a, _c, _d) = fresh();
        a.unlock(None, &Credential::password(PW)).unwrap();
        assert!(a.effective_signer().is_none());

        a.sign_unlock(None, &Credential::password(PW)).unwrap();
        assert!(a.effective_signer().is_some());
        assert!(a.status().sign_armed);

        a.consume_sign_grant();
        assert!(a.effective_signer().is_none());
        assert!(!a.status().sign_armed);

        a.sign_unlock(None, &Credential::password(PW)).unwrap();
        assert!(a.effective_signer().is_some());
    }

    #[test]
    fn decrypted_signer_is_not_retained_after_a_per_transaction_sign() {
        let (a, _c, _d) = fresh();
        a.sign_unlock(None, &Credential::password(PW)).unwrap();
        let weak = {
            let s = a.effective_signer().unwrap();
            std::sync::Arc::downgrade(&s)
        };
        a.consume_sign_grant();
        assert!(
            weak.upgrade().is_none(),
            "the decrypted signer must be dropped (not resident) after the signing operation"
        );
        assert!(a.effective_signer().is_none());
    }

    #[test]
    fn session_unlock_all_signs_repeatedly_only_when_opted_in() {
        let (a, _c, _d) = fresh();
        a.set_mode(
            None,
            UnlockMode::SessionUnlockAll,
            &Credential::password(PW),
        )
        .unwrap();
        a.unlock(None, &Credential::password(PW)).unwrap();
        assert!(a.effective_signer().is_some());
        a.consume_sign_grant();
        assert!(
            a.effective_signer().is_some(),
            "the held session signer survives grant consumption"
        );
        a.set_mode(None, UnlockMode::PerTransaction, &Credential::password(PW))
            .unwrap();
        assert!(
            a.effective_signer().is_none(),
            "switching to per-transaction drops the held signer"
        );
    }

    #[test]
    fn set_mode_to_session_requires_a_valid_credential() {
        // #432 Finding 3: a paired token alone must not silently weaken the posture.
        let (a, _c, _d) = fresh();
        let enroll = a.enroll_totp(None, &Credential::password(PW)).unwrap();
        // With TOTP active, set_mode→session needs the live code, not just the password.
        assert!(a
            .set_mode(
                None,
                UnlockMode::SessionUnlockAll,
                &Credential::password(PW)
            )
            .is_err());
        assert_eq!(a.mode(), UnlockMode::PerTransaction, "downgrade denied");
        let code = live_code(&enroll);
        assert!(a
            .set_mode(
                None,
                UnlockMode::SessionUnlockAll,
                &Credential::with_totp(PW, &code)
            )
            .is_ok());
        assert_eq!(a.mode(), UnlockMode::SessionUnlockAll);
    }

    #[test]
    fn wrong_password_denies_and_mutates_nothing() {
        let (a, _c, _d) = fresh();
        assert!(a.unlock(None, &Credential::password("wrong")).is_err());
        assert_eq!(a.status().state, AuthSessionState::Locked);
        assert!(a.sign_unlock(None, &Credential::password("wrong")).is_err());
        assert!(a.effective_signer().is_none());
        assert!(!a.status().sign_armed);
    }

    #[test]
    fn lock_drops_every_signer() {
        let (a, _c, _d) = fresh();
        a.set_mode(
            None,
            UnlockMode::SessionUnlockAll,
            &Credential::password(PW),
        )
        .unwrap();
        a.unlock(None, &Credential::password(PW)).unwrap();
        a.sign_unlock(None, &Credential::password(PW)).unwrap();
        assert!(a.effective_signer().is_some());
        a.lock();
        assert!(a.effective_signer().is_none());
        assert_eq!(a.status().state, AuthSessionState::Locked);
    }

    #[test]
    fn totp_enroll_then_verify_happy_and_wrong_code() {
        let (a, _c, _d) = fresh();
        let enroll = a.enroll_totp(None, &Credential::password(PW)).unwrap();
        assert!(!enroll.secret_base32.is_empty());
        assert!(enroll.otpauth_uri.starts_with("otpauth://totp/"));
        assert_eq!(a.method(), AuthMethod::Totp);

        let code = live_code(&enroll);
        assert!(
            a.unlock(None, &Credential::password(PW)).is_err(),
            "totp method requires a code"
        );
        assert!(a.unlock(None, &Credential::with_totp(PW, &code)).is_ok());
        assert!(a
            .unlock(None, &Credential::with_totp(PW, "000000"))
            .is_err());
        assert!(a
            .unlock(None, &Credential::with_totp("wrong", &code))
            .is_err());
    }

    #[test]
    fn totp_code_is_one_time_use_replay_rejected() {
        // #432 Finding B: a captured code must not replay within its ±skew validity window.
        let (a, _c, _d) = fresh();
        let enroll = a.enroll_totp(None, &Credential::password(PW)).unwrap();
        let code = live_code(&enroll);
        assert!(
            a.unlock(None, &Credential::with_totp(PW, &code)).is_ok(),
            "first use accepted"
        );
        let err = a
            .unlock(None, &Credential::with_totp(PW, &code))
            .unwrap_err();
        assert!(
            err.message.to_lowercase().contains("replay") || err.message.contains("already used"),
            "a replayed code must be rejected, got: {}",
            err.message
        );
    }

    #[test]
    fn concurrent_verify_of_one_code_accepts_exactly_once() {
        // #432 re-verify: TWO threads present the SAME live code at the same instant. The atomic
        // check-and-advance (single exclusive `config.write()` guard) must let EXACTLY ONE succeed —
        // a non-atomic read-then-write would let both pass `step <= last` and re-open the in-process
        // replay window (the stolen-password + captured-code threat TOTP backstops).
        let (a, _c, _d) = fresh();
        let enroll = a.enroll_totp(None, &Credential::password(PW)).unwrap();
        let code = live_code(&enroll);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (r1, r2) = std::thread::scope(|s| {
            let mk = |auth: UnlockAuth, code: String, bar: std::sync::Arc<std::sync::Barrier>| {
                s.spawn(move || {
                    bar.wait(); // align both threads onto verify_totp simultaneously
                    auth.unlock(None, &Credential::with_totp(PW, &code)).is_ok()
                })
            };
            let h1 = mk(a.clone(), code.clone(), barrier.clone());
            let h2 = mk(a.clone(), code.clone(), barrier.clone());
            (h1.join().unwrap(), h2.join().unwrap())
        });
        assert_eq!(
            [r1, r2].iter().filter(|ok| **ok).count(),
            1,
            "exactly one concurrent verify of the same code may succeed (atomic one-time-use)"
        );
    }

    #[test]
    fn enroll_totp_rotation_requires_the_current_factor() {
        // #432 Finding A: re-enrolling when a 2nd factor is active must require the LIVE code,
        // not just the password (else a stolen password re-enrolls the attacker's authenticator).
        let (a, _c, _d) = fresh();
        let enroll = a.enroll_totp(None, &Credential::password(PW)).unwrap();
        // Password-only rotation is now refused.
        assert!(
            a.enroll_totp(None, &Credential::password(PW)).is_err(),
            "rotation must require the current TOTP factor"
        );
        // With the live code it rotates to a NEW secret.
        let code = live_code(&enroll);
        let enroll2 = a
            .enroll_totp(None, &Credential::with_totp(PW, &code))
            .unwrap();
        assert_ne!(
            enroll.secret_base32, enroll2.secret_base32,
            "rotation issues a fresh secret"
        );
    }

    #[test]
    fn totp_is_node_level_and_works_across_wallets() {
        // #432 Decision 9: the 2nd factor is node-level, so a code enrolled via wallet A also
        // authorizes wallet B (with B's own password).
        let (a, custody, _d) = fresh();
        let b = custody.import(LEGAL, "passphrase-b", None).unwrap();
        custody.lock(None);
        let enroll = a.enroll_totp(None, &Credential::password(PW)).unwrap();

        // Unlock wallet B with B's password + the node-level code.
        let code = live_code(&enroll);
        assert!(a
            .unlock(Some(&b.id), &Credential::with_totp("passphrase-b", &code))
            .is_ok());
    }

    #[test]
    fn sign_grant_is_bound_to_its_wallet() {
        // #432 Decision 8: a grant armed for wallet A must not sign when B is the active wallet.
        let (a, custody, _d) = fresh();
        let wallet_a = custody.list()[0].id.clone(); // ABANDON = active
        let b = custody.import(LEGAL, "passphrase-b", None).unwrap();
        custody.select(&wallet_a).unwrap(); // A active
        custody.lock(None);

        // Arm a grant for A (the active wallet).
        a.sign_unlock(None, &Credential::password(PW)).unwrap();
        assert!(a.effective_signer().is_some(), "grant valid for active A");

        // Switch the active wallet to B → the A-bound grant no longer applies (fail closed).
        custody.select(&b.id).unwrap();
        assert!(
            a.effective_signer().is_none(),
            "a grant bound to A must not sign for the now-active B"
        );
    }

    #[test]
    fn set_method_back_to_password_requires_current_factor() {
        let (a, _c, _d) = fresh();
        let enroll = a.enroll_totp(None, &Credential::password(PW)).unwrap();
        assert!(a
            .set_method_password(None, &Credential::password(PW))
            .is_err());
        let code = live_code(&enroll);
        assert!(a
            .set_method_password(None, &Credential::with_totp(PW, &code))
            .is_ok());
        assert_eq!(a.method(), AuthMethod::Password);
        assert!(a.unlock(None, &Credential::password(PW)).is_ok());
    }

    #[test]
    fn passkey_enrollment_is_deferred_and_fails_closed() {
        let (a, _c, _d) = fresh();
        assert!(a
            .enroll_passkey_begin(None, &Credential::password(PW))
            .is_err());
        assert_eq!(a.method(), AuthMethod::Password);
    }

    #[test]
    fn mode_and_method_persist_across_reconstruction() {
        let (a, _c, dir) = fresh();
        a.set_mode(
            None,
            UnlockMode::SessionUnlockAll,
            &Credential::password(PW),
        )
        .unwrap();
        a.enroll_totp(None, &Credential::password(PW)).unwrap();

        let custody2 = WalletCustody::new(dir.clone(), Network::Mainnet, 3);
        let a2 = UnlockAuth::new(custody2, dir);
        assert_eq!(a2.mode(), UnlockMode::SessionUnlockAll);
        assert_eq!(a2.method(), AuthMethod::Totp);
        assert_eq!(a2.status().state, AuthSessionState::Locked);
        assert!(a2.effective_signer().is_none());
    }
}
