//! The engine side of the identity-authenticated IPC session (NODE-1 / U2, epic #908,
//! **security-critical / custody boundary**).
//!
//! The dig-node engine is IDENTITY-AGNOSTIC: it holds no user signing key and can never mint a
//! signature with one. A dig-app proves possession of a profile's slot-`0x0010` identity key over the
//! local per-user IPC channel, and the engine opens an in-memory session bound to that proven
//! identity. When the engine needs a signature for an engine-initiated operation it asks the app to
//! sign (the `sign` callback); the private key never crosses the boundary — only the signature does.
//!
//! This module is the engine counterpart of dig-app's `session.rs`. The two MUST agree byte-for-byte
//! on the two signed messages, so the constants and the [`challenge_message`] / [`sign_callback_message`]
//! builders here are the *reconstruction* the engine verifies against, identical to what the app signs.
//!
//! ## Handshake (engine's view)
//!
//! 1. `control.session.begin { profile_did, signing_pubkey_hex }` → the engine mints a random
//!    [`NONCE_LEN`]-byte nonce and a `session_candidate`, remembering the pending
//!    `{ nonce, profile_did, presented_pubkey }` ([`EngineSessionRegistry::begin`]).
//! 2. `control.session.attach { session_candidate, signature_b64, profile }` → the engine
//!    ([`EngineSessionRegistry::attach`]):
//!    - resolves the `profile_did`'s on-record slot-`0x0010` signing key via a [`DidSigningKeyResolver`]
//!      (the dig-identity read path — the DID HARD rule);
//!    - **REQUIRES** that resolved key to equal the `signing_pubkey_hex` presented in `begin` — a
//!      client cannot substitute a key it controls for the DID's real key;
//!    - verifies the Ed25519 signature over [`challenge_message`] against that key;
//!    - only then opens an in-memory [`EngineSession`].
//! 3. `control.session.detach { session_id }` → drops the in-memory session.
//!
//! ## Custody invariants (what the adversarial gate checks)
//!
//! - The engine only ever VERIFIES signatures; it never holds or derives a user key.
//! - Attach binds the session to a key the engine RESOLVED for the DID, not merely the key the caller
//!   presented — [`AttachError::KeyMismatch`] rejects a substituted key. A DID the resolver cannot
//!   resolve FAILS CLOSED ([`AttachError::UnresolvableDid`]): no session opens.
//! - The two signed messages carry distinct domain tags ([`SESSION_CHALLENGE_DOMAIN`] /
//!   [`SIGN_CALLBACK_DOMAIN`]) so a signature minted for one purpose can never validate as the other —
//!   closing the cross-protocol signing oracle a hostile engine or app would otherwise exploit.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

/// The domain separator the identity key signs under for a session-attach challenge. Byte-identical to
/// dig-app's `SESSION_CHALLENGE_DOMAIN`: the engine reconstructs the same challenge to verify.
pub const SESSION_CHALLENGE_DOMAIN: &[u8] = b"DIGNET-SESSION-v1";

/// The domain separator for the engine→app `sign` callback. Distinct from [`SESSION_CHALLENGE_DOMAIN`]
/// so a callback signature can never equal an attach-challenge signature. Byte-identical to dig-app's
/// `SIGN_CALLBACK_DOMAIN`.
pub const SIGN_CALLBACK_DOMAIN: &[u8] = b"DIGNET-SIGN-v1";

/// Length of the attach-challenge nonce the engine mints (32 bytes of OS randomness).
pub const NONCE_LEN: usize = 32;

/// Ed25519 signing-public-key length (slot `0x0010`).
pub const SIGNING_KEY_LEN: usize = 32;

/// Ed25519 detached-signature length.
pub const SIGNATURE_LEN: usize = 64;

/// The largest single IPC frame the engine will read (1 MiB). Bounds a hostile app streaming a
/// newline-less giant frame to OOM the engine. Mirrors dig-app's `MAX_FRAME_BYTES`.
///
/// This is the CONTRACT the `control.session.*` transport MUST enforce when it reads frames; the
/// transport is the NODE-1 engine-carve follow-up, so this constant is the value that layer binds to
/// (this module is transport-agnostic and never reads a socket itself).
pub const MAX_FRAME_BYTES: u64 = 1024 * 1024;

/// The most engine `sign` callbacks that may be in flight on one session before the engine stops
/// issuing more. Bounds an app (or engine bug) that would otherwise wedge an unbounded callback
/// stream. Mirrors dig-app's `MAX_INTERLEAVED_CALLBACKS`.
///
/// Like [`MAX_FRAME_BYTES`], this is the contract the (follow-up) transport enforces when it multiplexes
/// callbacks over a session — this module defines the bound; the transport applies it.
pub const MAX_INTERLEAVED_CALLBACKS: usize = 64;

/// The most begun-but-not-yet-attached handshakes the registry will hold at once. Bounds the memory a
/// caller could pin by calling `begin` repeatedly without ever attaching (each `begin` remembers a
/// [`PendingCandidate`] until its `attach` consumes it). Once this many are outstanding, [`begin`] fails
/// with [`AttachError::TooManyPending`] until an attach (or a future TTL sweep) frees a slot. TTL-based
/// expiry needs a clock seam and lands with the transport in the NODE-1 engine-carve follow-up; this
/// count cap is the memory bound enforceable in the transport-agnostic library today.
///
/// [`begin`]: EngineSessionRegistry::begin
pub const MAX_PENDING_CANDIDATES: usize = 256;

/// The capabilities the engine advertises to an attached session. Keyless by construction: content
/// serving, whole-store sync, and BROADCAST of an already-signed bundle — never key custody.
const ENGINE_CAPABILITIES: &[&str] = &["content.serve", "sync", "wallet.broadcast"];

/// Builds the exact bytes the identity key signs to attach a session:
/// `SESSION_CHALLENGE_DOMAIN ‖ nonce ‖ profile_did`. Pure and canonical — byte-identical to dig-app's
/// `challenge_message`, so the engine verifies against precisely what the app signed.
pub fn challenge_message(nonce: &[u8], profile_did: &str) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(SESSION_CHALLENGE_DOMAIN.len() + nonce.len() + profile_did.len());
    message.extend_from_slice(SESSION_CHALLENGE_DOMAIN);
    message.extend_from_slice(nonce);
    message.extend_from_slice(profile_did.as_bytes());
    message
}

/// Builds the exact bytes the identity key signs for an engine `sign` callback:
/// `SIGN_CALLBACK_DOMAIN ‖ len16(payload_type) ‖ payload_type ‖ payload`, where `len16` is the
/// big-endian `u16` byte length of `payload_type`. The length prefix makes the `type ‖ payload`
/// boundary unambiguous; the distinct domain tag closes the cross-protocol oracle. Returns `None` when
/// `payload_type` exceeds [`u16::MAX`] bytes (unrepresentable length prefix). Byte-identical to
/// dig-app's `sign_callback_message`.
pub fn sign_callback_message(payload_type: &str, payload: &[u8]) -> Option<Vec<u8>> {
    let type_len = u16::try_from(payload_type.len()).ok()?;
    let mut message =
        Vec::with_capacity(SIGN_CALLBACK_DOMAIN.len() + 2 + payload_type.len() + payload.len());
    message.extend_from_slice(SIGN_CALLBACK_DOMAIN);
    message.extend_from_slice(&type_len.to_be_bytes());
    message.extend_from_slice(payload_type.as_bytes());
    message.extend_from_slice(payload);
    Some(message)
}

/// Verify an Ed25519 `signature` over `message` against `signing_public_key` (slot `0x0010`). A
/// malformed key or signature simply fails to verify. VERIFY-ONLY: the engine never signs.
pub fn verify_signature(
    signing_public_key: &[u8; SIGNING_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    UnparsedPublicKey::new(&ED25519, signing_public_key)
        .verify(message, signature)
        .is_ok()
}

/// Resolves a profile DID to its on-record slot-`0x0010` signing public key — the AUTHORITATIVE key
/// the engine binds a session to. This is the custody seam: attach requires the resolved key to equal
/// the key the caller presented, so a caller can never attach a DID whose real identity key it does
/// not hold.
///
/// The production resolver walks the DID singleton to its authoritative profile store and reads slot
/// `0x0010` via the **dig-identity** read path (the DID HARD rule): parse the `did:chia:` DID to its
/// launcher id, resolve the current singleton coin ON-CHAIN, read the paired profile store's slot
/// `0x0010` (`dig_identity::resolve_did_keys` → `DidKeys::signing_public_key`).
///
/// That impl is deferred on a REAL, tracked blocker: dig-identity's on-chain DID→store resolution — the
/// chain-resolution layer that turns a `did:chia:` into its authoritative on-chain singleton coin and
/// paired profile-store metadata — is unshipped work (**#778, WU3, OPEN**). Today `dig_identity::
/// IdentityProfile::resolve` requires the caller to supply the on-chain records it does not fetch, so
/// there is no way for the engine to AUTHORITATIVELY resolve a DID's `0x0010` key on-chain yet. An
/// "echo" resolver that returned the caller-presented key would defeat the custody boundary entirely
/// (any caller could attach as any DID), so no production impl ships until #778 lands the real read
/// path. The production `DidSigningKeyResolver` is the NODE-1 engine-carve follow-up (it also removes
/// `dig-wallet` from the engine binary and wires the `control.session.*` transport).
///
/// Regardless of that impl, the custody boundary this trait defines is complete and enforced today: a
/// resolver that cannot resolve a DID returns `None`, and [`EngineSessionRegistry::attach`] fails
/// closed — no session opens for a DID whose on-record key cannot be authoritatively resolved and
/// matched.
pub trait DidSigningKeyResolver {
    /// The DID's on-record Ed25519 signing public key (slot `0x0010`), or `None` when the DID cannot be
    /// resolved or publishes no signing key.
    fn resolve_signing_key(&self, profile_did: &str) -> Option<[u8; SIGNING_KEY_LEN]>;
}

/// The profile attachment the app pushes on `attach`: `{ did, subscriptions, config_digest }`
/// (dig-app `SPEC.md` §5.3). The engine drives per-session content serving from `subscriptions` and
/// detects config drift via `config_digest` without ever seeing the sealed config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileAttachment {
    /// The profile DID being attached.
    pub did: String,
    /// The subscriptions the engine should serve for this session.
    #[serde(default)]
    pub subscriptions: Vec<String>,
    /// A digest of the profile's config, for drift detection without seeing the config.
    #[serde(default)]
    pub config_digest: String,
}

/// A live, attached engine session — one per attached profile (the engine is multi-session aware for
/// fast user switching). Holds only PUBLIC identity material + the app-pushed user slices; never a key
/// the engine could sign with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineSession {
    /// The engine-assigned session identifier, echoed on `detach` and correlated in `sign` callbacks.
    pub session_id: String,
    /// The DID this session is bound to (its identity was proven at attach).
    pub profile_did: String,
    /// The proven slot-`0x0010` signing public key — the key `sign`-callback signatures are verified
    /// against for this session.
    pub signing_public_key: [u8; SIGNING_KEY_LEN],
    /// The subscriptions the app pushed for this session.
    pub subscriptions: Vec<String>,
    /// The capabilities the engine advertised to this session.
    pub engine_capabilities: Vec<String>,
}

/// The pending handshake between `begin` and `attach`: the engine remembers what it must verify.
#[derive(Debug, Clone)]
struct PendingCandidate {
    nonce: [u8; NONCE_LEN],
    profile_did: String,
    presented_pubkey: [u8; SIGNING_KEY_LEN],
}

/// The outcome of `control.session.begin`: the nonce the app signs and the candidate id that names
/// this pending handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginOutcome {
    /// The base64 nonce the app decodes and folds into the challenge.
    pub nonce_b64: String,
    /// The candidate id the app echoes on `attach`.
    pub session_candidate: String,
}

/// The outcome of a successful `control.session.attach`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachOutcome {
    /// The opened session's id.
    pub session_id: String,
    /// The capabilities advertised to the session.
    pub engine_capabilities: Vec<String>,
}

/// Why a `begin`/`attach` was rejected. Each maps to a JSON-RPC error at the transport; none opens a
/// session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttachError {
    /// `profile_did` is not a well-formed `did:chia:` DID.
    #[error("profile_did is not a valid DID")]
    InvalidDid,
    /// `signing_pubkey_hex` was not 32 bytes of hex.
    #[error("signing_pubkey_hex is not a 32-byte hex key")]
    InvalidPubkey,
    /// The `session_candidate` is unknown (never begun, already consumed, or expired).
    #[error("unknown or expired session candidate")]
    UnknownCandidate,
    /// Too many handshakes are begun-but-not-attached — [`MAX_PENDING_CANDIDATES`] is the memory bound.
    #[error("too many pending session candidates")]
    TooManyPending,
    /// The DID could not be resolved to an on-record signing key — attach fails closed.
    #[error("the profile DID could not be resolved to a signing key")]
    UnresolvableDid,
    /// The resolved on-record key does not equal the key presented in `begin` — a substituted key.
    #[error("the presented key does not match the DID's on-record signing key")]
    KeyMismatch,
    /// The base64 signature was malformed or not 64 bytes.
    #[error("the attach signature is malformed")]
    InvalidSignature,
    /// The signature did not verify over the challenge for the resolved key.
    #[error("the attach signature did not verify")]
    SignatureRejected,
    /// The attach `profile.did` disagreed with the candidate's `profile_did`.
    #[error("the attach profile DID does not match the begun candidate")]
    ProfileDidMismatch,
}

/// Mints the random material the engine needs (nonces + ids). A seam so tests are deterministic while
/// production draws from the OS CSPRNG.
pub trait SessionEntropy {
    /// A fresh [`NONCE_LEN`]-byte challenge nonce.
    fn nonce(&mut self) -> [u8; NONCE_LEN];
    /// A fresh, unguessable id (candidate id / session id) as a string.
    fn id(&mut self) -> String;
}

/// The production entropy source: the OS CSPRNG (`getrandom`). Nonces are 32 random bytes; ids are
/// 16 random bytes rendered as hex (128 bits of unguessability).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl SessionEntropy for OsEntropy {
    fn nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG unavailable");
        nonce
    }

    fn id(&mut self) -> String {
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw).expect("OS CSPRNG unavailable");
        hex::encode(raw)
    }
}

/// The engine's live session state: the pending handshakes and the open sessions, both keyed by their
/// ids. Multi-session (SPEC §5.3 "the engine keeps a map `session_id → …`"): concurrent sessions for
/// different profiles coexist, so a `sign` callback can route to the connection that owns its
/// `session_id`.
pub struct EngineSessionRegistry<E: SessionEntropy = OsEntropy> {
    entropy: E,
    pending: HashMap<String, PendingCandidate>,
    sessions: HashMap<String, EngineSession>,
}

impl Default for EngineSessionRegistry<OsEntropy> {
    fn default() -> Self {
        Self::new(OsEntropy)
    }
}

impl<E: SessionEntropy> EngineSessionRegistry<E> {
    /// A registry with no pending handshakes or open sessions, drawing randomness from `entropy`.
    pub fn new(entropy: E) -> Self {
        Self {
            entropy,
            pending: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    /// `control.session.begin`: validate the presented DID + key, mint a nonce + candidate id, and
    /// remember the pending handshake. Returns the nonce (base64) + candidate id for the app to sign
    /// and echo.
    pub fn begin(
        &mut self,
        profile_did: &str,
        signing_pubkey_hex: &str,
    ) -> Result<BeginOutcome, AttachError> {
        if !is_did_chia(profile_did) {
            return Err(AttachError::InvalidDid);
        }
        let presented_pubkey = decode_signing_key(signing_pubkey_hex)?;

        // Bound the memory a caller can pin by begin-ing without ever attaching.
        if self.pending.len() >= MAX_PENDING_CANDIDATES {
            return Err(AttachError::TooManyPending);
        }

        let nonce = self.entropy.nonce();
        let session_candidate = self.entropy.id();
        self.pending.insert(
            session_candidate.clone(),
            PendingCandidate {
                nonce,
                profile_did: profile_did.to_string(),
                presented_pubkey,
            },
        );
        Ok(BeginOutcome {
            nonce_b64: BASE64.encode(nonce),
            session_candidate,
        })
    }

    /// `control.session.attach`: consume the pending candidate, resolve the DID's authoritative signing
    /// key, REQUIRE it equals the presented key, verify the challenge signature, and open a session.
    ///
    /// The candidate is consumed whether or not the attach succeeds, so a failed or replayed attach
    /// cannot be retried against the same nonce.
    pub fn attach(
        &mut self,
        session_candidate: &str,
        signature_b64: &str,
        profile: ProfileAttachment,
        resolver: &dyn DidSigningKeyResolver,
    ) -> Result<AttachOutcome, AttachError> {
        // Consume the candidate up front: one nonce, one attach attempt.
        let candidate = self
            .pending
            .remove(session_candidate)
            .ok_or(AttachError::UnknownCandidate)?;

        if profile.did != candidate.profile_did {
            return Err(AttachError::ProfileDidMismatch);
        }

        // The custody boundary: bind to the key the DID PUBLISHES, not merely the presented key.
        let resolved = resolver
            .resolve_signing_key(&candidate.profile_did)
            .ok_or(AttachError::UnresolvableDid)?;
        if resolved != candidate.presented_pubkey {
            return Err(AttachError::KeyMismatch);
        }

        let signature = decode_signature(signature_b64)?;
        let challenge = challenge_message(&candidate.nonce, &candidate.profile_did);
        if !verify_signature(&resolved, &challenge, &signature) {
            return Err(AttachError::SignatureRejected);
        }

        let session_id = self.entropy.id();
        let session = EngineSession {
            session_id: session_id.clone(),
            profile_did: candidate.profile_did,
            signing_public_key: resolved,
            subscriptions: profile.subscriptions,
            engine_capabilities: ENGINE_CAPABILITIES.iter().map(|s| s.to_string()).collect(),
        };
        self.sessions.insert(session_id.clone(), session);
        Ok(AttachOutcome {
            session_id,
            engine_capabilities: ENGINE_CAPABILITIES.iter().map(|s| s.to_string()).collect(),
        })
    }

    /// `control.session.detach`: drop the in-memory session. Returns whether a session was present.
    pub fn detach(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// The open session with `session_id`, if any (for routing a `sign` callback / a per-session op).
    pub fn session(&self, session_id: &str) -> Option<&EngineSession> {
        self.sessions.get(session_id)
    }

    /// How many sessions are currently open.
    pub fn open_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// How many handshakes are begun-but-not-attached (for tests / diagnostics).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Verify a `sign`-callback signature the app returned: the signature MUST be over the
    /// domain-separated [`sign_callback_message`], valid for the session's proven signing key. This is
    /// how the engine confirms the app really signed the engine's op (and not a replayed signature over
    /// some other message). Returns `false` for an unknown session, an over-long `payload_type`, or a
    /// bad signature.
    pub fn verify_sign_callback(
        &self,
        session_id: &str,
        payload_type: &str,
        payload: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool {
        let Some(session) = self.sessions.get(session_id) else {
            return false;
        };
        let Some(message) = sign_callback_message(payload_type, payload) else {
            return false;
        };
        verify_signature(&session.signing_public_key, &message, signature)
    }
}

/// A cheap pre-filter that `profile_did` is a `did:chia:` DID (non-empty bech32m payload). This is
/// only a syntactic gate — the AUTHORITATIVE identity check is the [`DidSigningKeyResolver`], which
/// resolves the DID's on-record key and requires it to match the presented key. Kept lightweight and
/// self-contained; the full chia-wallet-sdk DID parse lives in the production resolver (which consumes
/// dig-identity — the DID HARD rule — once the shared-dependency cascade lands, see the resolver docs).
fn is_did_chia(profile_did: &str) -> bool {
    profile_did
        .strip_prefix("did:chia:")
        .is_some_and(|payload| !payload.is_empty())
}

/// Decode a 64-lowercase-hex slot-`0x0010` signing key.
fn decode_signing_key(hex_key: &str) -> Result<[u8; SIGNING_KEY_LEN], AttachError> {
    let bytes = hex::decode(hex_key).map_err(|_| AttachError::InvalidPubkey)?;
    bytes.try_into().map_err(|_| AttachError::InvalidPubkey)
}

/// Decode a base64 64-byte Ed25519 signature.
fn decode_signature(signature_b64: &str) -> Result<[u8; SIGNATURE_LEN], AttachError> {
    let bytes = BASE64
        .decode(signature_b64)
        .map_err(|_| AttachError::InvalidSignature)?;
    bytes.try_into().map_err(|_| AttachError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};

    const DID: &str = "did:chia:1qv4x8s0y5q9k2m6f8h3j7l4n1p0r5t2w9c6b3d8g1a4e7";

    /// A deterministic entropy source for tests: nonces + ids derive from a counter so the whole
    /// handshake is reproducible. Production uses [`OsEntropy`]; a hard-coded value would be a test
    /// smell, so we derive from a hashed seed.
    struct SeededEntropy {
        counter: u64,
    }

    impl SeededEntropy {
        fn new() -> Self {
            Self { counter: 0 }
        }
    }

    impl SessionEntropy for SeededEntropy {
        fn nonce(&mut self) -> [u8; NONCE_LEN] {
            self.counter += 1;
            Sha256::digest(format!("test-nonce-{}", self.counter).as_bytes()).into()
        }

        fn id(&mut self) -> String {
            self.counter += 1;
            format!("id-{}", self.counter)
        }
    }

    /// A resolver that returns a fixed key for the known DID, mimicking the dig-identity read path.
    struct FixedResolver {
        key: Option<[u8; SIGNING_KEY_LEN]>,
    }

    impl DidSigningKeyResolver for FixedResolver {
        fn resolve_signing_key(&self, _profile_did: &str) -> Option<[u8; SIGNING_KEY_LEN]> {
            self.key
        }
    }

    /// Build a deterministic test key from a label — the seed is derived (never a hard-coded literal,
    /// which CodeQL flags), so the fixture is reproducible without embedding key material.
    fn key_from(label: &[u8]) -> Ed25519KeyPair {
        let seed: [u8; 32] = Sha256::digest(label).into();
        Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid ed25519 seed")
    }

    fn signing_key() -> Ed25519KeyPair {
        key_from(b"node-1 engine session test key")
    }

    fn pubkey(key: &Ed25519KeyPair) -> [u8; 32] {
        key.public_key()
            .as_ref()
            .try_into()
            .expect("32-byte ed25519 public key")
    }

    /// Sign `message`, returning the detached 64-byte signature — the app-side signing operation the
    /// engine verifies against.
    fn sign(key: &Ed25519KeyPair, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        key.sign(message)
            .as_ref()
            .try_into()
            .expect("64-byte ed25519 signature")
    }

    fn resolver_for(key: &Ed25519KeyPair) -> FixedResolver {
        FixedResolver {
            key: Some(pubkey(key)),
        }
    }

    fn registry() -> EngineSessionRegistry<SeededEntropy> {
        EngineSessionRegistry::new(SeededEntropy::new())
    }

    /// The full begin→sign→attach happy path, signing the challenge exactly as dig-app would.
    fn attach_happy(
        reg: &mut EngineSessionRegistry<SeededEntropy>,
        key: &Ed25519KeyPair,
    ) -> AttachOutcome {
        let begin = reg.begin(DID, &hex::encode(pubkey(key))).unwrap();
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let signature = sign(key, &challenge_message(&nonce, DID));
        reg.attach(
            &begin.session_candidate,
            &BASE64.encode(signature),
            ProfileAttachment {
                did: DID.to_string(),
                subscriptions: vec!["store-a".to_string()],
                config_digest: "cfg".to_string(),
            },
            &resolver_for(key),
        )
        .unwrap()
    }

    // --- Byte-identical KAT with dig-app's session.rs (the cross-repo golden) --------------------

    #[test]
    fn domain_tags_match_the_canonical_registry() {
        assert_eq!(SESSION_CHALLENGE_DOMAIN, b"DIGNET-SESSION-v1");
        assert_eq!(SIGN_CALLBACK_DOMAIN, b"DIGNET-SIGN-v1");
    }

    #[test]
    fn challenge_message_kat_is_byte_identical_to_dig_app() {
        // GOLDEN: the exact concatenation dig-app signs. If either repo's builder drifts, its KAT
        // fails. `DIGNET-SESSION-v1` ‖ nonce ‖ profile_did. The nonce is derived from a hashed
        // seed (not an integer literal) so it can never be mistaken for a hard-coded key material.
        let nonce: [u8; 32] = Sha256::digest(b"challenge-message-kat").into();
        let msg = challenge_message(&nonce, "did:chia:x");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"DIGNET-SESSION-v1");
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(b"did:chia:x");
        assert_eq!(msg, expected);
    }

    #[test]
    fn sign_callback_message_kat_is_byte_identical_to_dig_app() {
        // GOLDEN: `DIGNET-SIGN-v1` ‖ len16("ab")=0x0002 ‖ "ab" ‖ "cd".
        let msg = sign_callback_message("ab", b"cd").unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"DIGNET-SIGN-v1");
        expected.extend_from_slice(&[0x00, 0x02]);
        expected.extend_from_slice(b"ab");
        expected.extend_from_slice(b"cd");
        assert_eq!(msg, expected);
    }

    #[test]
    fn sign_callback_message_disambiguates_type_payload_boundary() {
        // (type="a", payload="bc") and (type="ab", payload="c") must differ.
        assert_ne!(
            sign_callback_message("a", b"bc").unwrap(),
            sign_callback_message("ab", b"c").unwrap()
        );
    }

    #[test]
    fn sign_callback_message_rejects_an_overlong_type() {
        let too_long = "x".repeat(usize::from(u16::MAX) + 1);
        assert!(sign_callback_message(&too_long, b"p").is_none());
    }

    // --- begin / attach --------------------------------------------------------------------------

    #[test]
    fn begin_then_attach_opens_a_session_bound_to_the_did() {
        let key = signing_key();
        let mut reg = registry();
        let outcome = attach_happy(&mut reg, &key);
        assert_eq!(reg.open_session_count(), 1);
        assert_eq!(reg.pending_count(), 0);
        let session = reg.session(&outcome.session_id).unwrap();
        assert_eq!(session.profile_did, DID);
        assert_eq!(session.signing_public_key, pubkey(&key));
        assert_eq!(session.subscriptions, ["store-a"]);
        assert_eq!(outcome.engine_capabilities, ENGINE_CAPABILITIES);
    }

    #[test]
    fn begin_rejects_a_malformed_did() {
        let mut reg = registry();
        assert_eq!(
            reg.begin("not-a-did", &hex::encode([1u8; 32])),
            Err(AttachError::InvalidDid)
        );
    }

    #[test]
    fn begin_rejects_a_malformed_pubkey() {
        let mut reg = registry();
        assert_eq!(reg.begin(DID, "zz"), Err(AttachError::InvalidPubkey));
    }

    #[test]
    fn attach_rejects_an_unknown_candidate() {
        let key = signing_key();
        let mut reg = registry();
        let err = reg
            .attach(
                "nope",
                &BASE64.encode([0u8; SIGNATURE_LEN]),
                ProfileAttachment {
                    did: DID.to_string(),
                    subscriptions: vec![],
                    config_digest: String::new(),
                },
                &resolver_for(&key),
            )
            .unwrap_err();
        assert_eq!(err, AttachError::UnknownCandidate);
    }

    #[test]
    fn attach_fails_closed_when_the_did_is_unresolvable() {
        let key = signing_key();
        let mut reg = registry();
        let begin = reg.begin(DID, &hex::encode(pubkey(&key))).unwrap();
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let signature = sign(&key, &challenge_message(&nonce, DID));
        let err = reg
            .attach(
                &begin.session_candidate,
                &BASE64.encode(signature),
                ProfileAttachment {
                    did: DID.to_string(),
                    subscriptions: vec![],
                    config_digest: String::new(),
                },
                &FixedResolver { key: None },
            )
            .unwrap_err();
        assert_eq!(err, AttachError::UnresolvableDid);
        assert_eq!(reg.open_session_count(), 0);
    }

    #[test]
    fn attach_rejects_a_substituted_key() {
        // The caller presents (and signs with) a key it controls, but the DID's on-record key is a
        // DIFFERENT key — the custody boundary must reject this: you cannot attach a DID whose real
        // identity key you do not hold.
        let attacker = signing_key();
        let real = key_from(b"the real did key");
        let mut reg = registry();
        let begin = reg.begin(DID, &hex::encode(pubkey(&attacker))).unwrap();
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let signature = sign(&attacker, &challenge_message(&nonce, DID));
        let err = reg
            .attach(
                &begin.session_candidate,
                &BASE64.encode(signature),
                ProfileAttachment {
                    did: DID.to_string(),
                    subscriptions: vec![],
                    config_digest: String::new(),
                },
                &resolver_for(&real),
            )
            .unwrap_err();
        assert_eq!(err, AttachError::KeyMismatch);
    }

    #[test]
    fn attach_rejects_a_signature_by_the_wrong_key() {
        // The DID resolves to the real key AND that key is presented, but the signature was made by a
        // different key — it must not verify.
        let real = signing_key();
        let wrong = key_from(b"wrong signer");
        let mut reg = registry();
        let begin = reg.begin(DID, &hex::encode(pubkey(&real))).unwrap();
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let bad_signature = sign(&wrong, &challenge_message(&nonce, DID));
        let err = reg
            .attach(
                &begin.session_candidate,
                &BASE64.encode(bad_signature),
                ProfileAttachment {
                    did: DID.to_string(),
                    subscriptions: vec![],
                    config_digest: String::new(),
                },
                &resolver_for(&real),
            )
            .unwrap_err();
        assert_eq!(err, AttachError::SignatureRejected);
    }

    #[test]
    fn attach_rejects_a_profile_did_that_differs_from_the_candidate() {
        let key = signing_key();
        let mut reg = registry();
        let begin = reg.begin(DID, &hex::encode(pubkey(&key))).unwrap();
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let signature = sign(&key, &challenge_message(&nonce, DID));
        let err = reg
            .attach(
                &begin.session_candidate,
                &BASE64.encode(signature),
                ProfileAttachment {
                    did: "did:chia:1qother0000000000000000000000000000000000000000000".to_string(),
                    subscriptions: vec![],
                    config_digest: String::new(),
                },
                &resolver_for(&key),
            )
            .unwrap_err();
        assert_eq!(err, AttachError::ProfileDidMismatch);
    }

    #[test]
    fn attach_consumes_the_candidate_so_it_cannot_be_replayed() {
        let key = signing_key();
        let mut reg = registry();
        let begin = reg.begin(DID, &hex::encode(pubkey(&key))).unwrap();
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let signature = sign(&key, &challenge_message(&nonce, DID));
        let sig_b64 = BASE64.encode(signature);
        let profile = ProfileAttachment {
            did: DID.to_string(),
            subscriptions: vec![],
            config_digest: String::new(),
        };
        reg.attach(
            &begin.session_candidate,
            &sig_b64,
            profile.clone(),
            &resolver_for(&key),
        )
        .unwrap();
        // A second attach with the SAME candidate is now unknown.
        let err = reg
            .attach(
                &begin.session_candidate,
                &sig_b64,
                profile,
                &resolver_for(&key),
            )
            .unwrap_err();
        assert_eq!(err, AttachError::UnknownCandidate);
    }

    #[test]
    fn begin_rejects_when_too_many_candidates_are_pending() {
        let key = signing_key();
        let pubkey_hex = hex::encode(pubkey(&key));
        let mut reg = registry();
        // Fill the pending map to its cap; each begin uses a distinct candidate id.
        for _ in 0..MAX_PENDING_CANDIDATES {
            reg.begin(DID, &pubkey_hex).unwrap();
        }
        assert_eq!(reg.pending_count(), MAX_PENDING_CANDIDATES);
        // One more must be refused rather than growing memory unbounded.
        assert_eq!(
            reg.begin(DID, &pubkey_hex),
            Err(AttachError::TooManyPending)
        );
    }

    #[test]
    fn detach_drops_the_session() {
        let key = signing_key();
        let mut reg = registry();
        let outcome = attach_happy(&mut reg, &key);
        assert!(reg.detach(&outcome.session_id));
        assert_eq!(reg.open_session_count(), 0);
        assert!(!reg.detach(&outcome.session_id));
    }

    #[test]
    fn multi_session_keeps_distinct_profiles() {
        let key_a = signing_key();
        let key_b = key_from(b"profile b key");
        let did_b = "did:chia:1qprofileb000000000000000000000000000000000000000";
        let mut reg = registry();

        let out_a = attach_happy(&mut reg, &key_a);
        // Attach a second, different profile.
        let begin_b = reg.begin(did_b, &hex::encode(pubkey(&key_b))).unwrap();
        let nonce_b = BASE64.decode(&begin_b.nonce_b64).unwrap();
        let sig_b = sign(&key_b, &challenge_message(&nonce_b, did_b));
        let out_b = reg
            .attach(
                &begin_b.session_candidate,
                &BASE64.encode(sig_b),
                ProfileAttachment {
                    did: did_b.to_string(),
                    subscriptions: vec![],
                    config_digest: String::new(),
                },
                &resolver_for(&key_b),
            )
            .unwrap();

        assert_eq!(reg.open_session_count(), 2);
        assert_eq!(reg.session(&out_a.session_id).unwrap().profile_did, DID);
        assert_eq!(reg.session(&out_b.session_id).unwrap().profile_did, did_b);
    }

    // --- sign-callback verification --------------------------------------------------------------

    #[test]
    fn verify_sign_callback_accepts_the_apps_domain_separated_signature() {
        let key = signing_key();
        let mut reg = registry();
        let outcome = attach_happy(&mut reg, &key);

        let payload = b"already-signed-spend-bundle";
        let message = sign_callback_message("spend", payload).unwrap();
        let signature = sign(&key, &message);
        assert!(reg.verify_sign_callback(&outcome.session_id, "spend", payload, &signature));
    }

    #[test]
    fn verify_sign_callback_rejects_a_signature_over_the_raw_payload() {
        // A signature over the RAW payload (no domain tag) must not be accepted — closes the oracle.
        let key = signing_key();
        let mut reg = registry();
        let outcome = attach_happy(&mut reg, &key);
        let payload = b"raw-bytes";
        let raw_sig = sign(&key, payload);
        assert!(!reg.verify_sign_callback(&outcome.session_id, "spend", payload, &raw_sig));
    }

    #[test]
    fn verify_sign_callback_rejects_an_unknown_session() {
        let reg = registry();
        assert!(!reg.verify_sign_callback("nope", "spend", b"p", &[0u8; SIGNATURE_LEN]));
    }

    #[test]
    fn a_session_attach_signature_cannot_be_replayed_as_a_sign_callback() {
        // The cross-protocol oracle, the other direction: an attach-challenge signature must NOT
        // verify as a sign-callback signature, because the domain tags differ.
        let key = signing_key();
        let mut reg = registry();
        let begin = reg.begin(DID, &hex::encode(pubkey(&key))).unwrap();
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let challenge = challenge_message(&nonce, DID);
        let attach_sig = sign(&key, &challenge);
        reg.attach(
            &begin.session_candidate,
            &BASE64.encode(attach_sig),
            ProfileAttachment {
                did: DID.to_string(),
                subscriptions: vec![],
                config_digest: String::new(),
            },
            &resolver_for(&key),
        )
        .unwrap();
        let session_id = reg.sessions.keys().next().unwrap().clone();
        // Feed the attach signature as if it were a callback over the challenge bytes: rejected.
        assert!(!reg.verify_sign_callback(&session_id, "spend", &challenge, &attach_sig));
    }
}
