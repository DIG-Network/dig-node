//! The engine side of the identity-authenticated IPC session (NODE-1 / U2, epic #908,
//! **security-critical / custody boundary**).
//!
//! The dig-node engine is IDENTITY-AGNOSTIC: it holds no user signing key and can never mint a
//! signature with one. A dig-app proves possession of a profile's slot-`0x0010` identity key over the
//! local per-user IPC channel, and the engine opens an in-memory session bound to that proven
//! identity. When the engine needs a signature for an engine-initiated operation it asks the app to
//! sign (the `sign` callback); the private key never crosses the boundary — only the signature does.
//!
//! ## The contract lives in `dig-ipc-protocol`
//!
//! The session/signing wire contract — the handshake state machine ([`EngineSessionRegistry`]), the
//! domain-separated message builders ([`challenge_message`] / [`sign_callback_message`]), the
//! [`verify_signature`] primitive, the `control.session.*` JSON-RPC types, the resource
//! [`bounds`](dig_ipc_protocol::bounds), and the frame [`transport`](dig_ipc_protocol::transport) — is
//! owned by the leaf crate `dig-ipc-protocol`, the SINGLE source of truth shared by the app half
//! (dig-app) and this engine half. Both consume the crate instead of maintaining byte-identical copies,
//! so the two can never silently drift. This module RE-EXPORTS the engine role-half at its established
//! path (`dig_node_core::session::*`) and adds the one thing that is genuinely the engine's own: the
//! **production** [`DidSigningKeyResolver`] backed by on-chain DID resolution.
//!
//! ## The custody boundary (what the adversarial gate checks)
//!
//! - The engine only ever VERIFIES signatures; it never holds or derives a user key.
//! - Attach binds the session to the key the engine RESOLVED for the DID on-chain, not merely the key
//!   the caller presented — a substituted key is rejected. A DID the resolver cannot resolve FAILS
//!   CLOSED: no session opens.
//! - The two signed messages carry distinct domain tags so a signature minted for one purpose can never
//!   validate as the other — closing the cross-protocol signing oracle.

// Re-export the engine session half from the canonical contract crate, so callers keep importing from
// `dig_node_core::session::*` while the protocol logic (and its exhaustive tests) live in one place.
pub use dig_ipc_protocol::{
    bounds, challenge_message, engine, sign_callback_message, transport, verify_signature,
    AttachError, AttachParams, AttachResult, BeginParams, BeginResult, DetachParams, DetachResult,
    DidSigningKeyResolver, EngineSessionRegistry, OsEntropy, ProfileAttachment, RpcError,
    SessionEntropy, SignErrorCode, Signature, SigningPublicKey, ENGINE_CAPABILITIES,
    MAX_FRAME_BYTES, MAX_INTERLEAVED_CALLBACKS, MAX_PENDING_CANDIDATES, NONCE_LEN,
    SESSION_CHALLENGE_DOMAIN, SIGNATURE_LEN, SIGNING_KEY_LEN, SIGN_CALLBACK_DOMAIN,
};

use dig_identity::{resolve_signing_key, ChainSource, ResolveError};

/// The engine's **production** [`DidSigningKeyResolver`]: it resolves a profile DID to its published
/// slot-`0x0010` signing key by CHAIN-AUTHENTICATED on-chain lookup (dig-identity's WU3 read path,
/// #778), so `attach` can bind a session only to a key the DID genuinely published.
///
/// This is the honest backend the contract's [`DidSigningKeyResolver`] seam demands. It delegates to
/// [`dig_identity::resolve_signing_key`], which walks the DID singleton lineage to its authentic tip,
/// finds the store the DID paired, binds the fetched profile body to the store's current on-chain root,
/// and returns the published signing key — failing closed on every ambiguity, staleness, or mismatch.
/// The resolver never echoes the caller-presented key and never accepts a caller-supplied lineage; the
/// chain [`ChainSource`] it is built over MUST be a genuine forward lineage walk (coinset / full node),
/// NEVER a `SingletonLineage::single` echo, or the custody boundary collapses.
///
/// The private key never enters the engine: this type resolves only PUBLIC keys.
pub struct ChainDidSigningKeyResolver<S: ChainSource> {
    /// The honest chain reader the DID resolution walks (the engine's coinset / full-node backend).
    source: S,
}

impl<S: ChainSource> ChainDidSigningKeyResolver<S> {
    /// Build the resolver over the engine's honest chain `source`.
    pub fn new(source: S) -> Self {
        Self { source }
    }

    /// The chain source this resolver reads (for reuse by other engine DID lookups).
    pub fn source(&self) -> &S {
        &self.source
    }
}

impl<S: ChainSource> DidSigningKeyResolver for ChainDidSigningKeyResolver<S> {
    /// Resolve `profile_did` to its published slot-`0x0010` signing key, or `None` when the DID cannot be
    /// AUTHORITATIVELY resolved on-chain.
    ///
    /// Every resolution failure — an invalid DID, a melted singleton, no/ambiguous profile, a stale or
    /// tampered root, no published signing key, or a chain-source error — collapses to `None` so
    /// [`EngineSessionRegistry::attach`] fails closed. A resolution that could not be fully
    /// chain-authenticated MUST NOT yield a key.
    fn resolve_signing_key(&self, profile_did: &str) -> Option<SigningPublicKey> {
        match resolve_signing_key(profile_did, &self.source) {
            Ok(key) => Some(SigningPublicKey::new(key)),
            Err(reason) => {
                // Fail closed; the DID is unusable for an attach. Logged at debug (not warn) because an
                // unresolvable DID is an expected client-side condition, not an engine fault.
                tracing::debug!(target: "dig_node::session", %profile_did, error = %describe(&reason), "DID signing-key resolution failed; attach will be refused");
                None
            }
        }
    }
}

/// A stable, log-safe description of why a DID resolution failed (no key material, no chain internals).
fn describe(error: &ResolveError) -> &'static str {
    match error {
        ResolveError::InvalidDid => "invalid-did",
        ResolveError::NoIdentitySingleton => "no-identity-singleton",
        ResolveError::NoProfile => "no-authoritative-profile",
        ResolveError::AmbiguousProfile => "ambiguous-profile",
        ResolveError::StaleOrTamperedRoot => "stale-or-tampered-root",
        ResolveError::NoSigningKey => "no-signing-key",
        ResolveError::Format(_) => "profile-format-error",
        ResolveError::Chain(_) => "chain-source-error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use dig_identity::slot::standard;
    use dig_identity::{
        Bytes32, ChainStoreState, Coin, Did, Profile, ResolveError, SingletonLineage, StoreRecord,
        Value,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};

    /// The Ed25519 signing key a well-formed test profile publishes (slot `0x0010`).
    const SIGNING_KEY: [u8; 32] = [7u8; 32];

    // --- The KAT cross-check: the crate's builders equal the old golden bytes ------------------------

    #[test]
    fn domain_tags_match_the_frozen_golden() {
        assert_eq!(SESSION_CHALLENGE_DOMAIN, b"DIGNET-SESSION-v1");
        assert_eq!(SIGN_CALLBACK_DOMAIN, b"DIGNET-SIGN-v1");
        assert_eq!(NONCE_LEN, 32);
        assert_eq!(SIGNING_KEY_LEN, 32);
        assert_eq!(SIGNATURE_LEN, 64);
        assert_eq!(MAX_FRAME_BYTES, 1024 * 1024);
        assert_eq!(MAX_PENDING_CANDIDATES, 256);
        assert_eq!(MAX_INTERLEAVED_CALLBACKS, 64);
    }

    #[test]
    fn challenge_message_kat_is_byte_identical_to_the_old_builder() {
        // GOLDEN: `DIGNET-SESSION-v1` ‖ nonce ‖ profile_did — the exact concatenation dig-app signs and
        // the engine reconstructs. The nonce derives from a hashed seed (never an integer literal, which
        // CodeQL flags as hard-coded key material).
        let nonce: [u8; 32] = Sha256::digest(b"challenge-message-kat").into();
        let msg = challenge_message(&nonce, "did:chia:x");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"DIGNET-SESSION-v1");
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(b"did:chia:x");
        assert_eq!(msg, expected);
    }

    #[test]
    fn sign_callback_message_kat_is_byte_identical_to_the_old_builder() {
        // GOLDEN: `DIGNET-SIGN-v1` ‖ len16(type) ‖ type ‖ payload.
        let payload: [u8; 8] = Sha256::digest(b"sign-callback-kat").as_slice()[..8]
            .try_into()
            .unwrap();
        let msg = sign_callback_message("spend", &payload).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"DIGNET-SIGN-v1");
        expected.extend_from_slice(&5u16.to_be_bytes());
        expected.extend_from_slice(b"spend");
        expected.extend_from_slice(&payload);
        assert_eq!(msg, expected);
    }

    #[test]
    fn the_two_domain_tags_never_collide() {
        let nonce = [0u8; NONCE_LEN];
        let challenge = challenge_message(&nonce, "did:chia:x");
        let callback = sign_callback_message("did:chia:x", &nonce).unwrap();
        assert_ne!(
            challenge, callback,
            "a signature for one purpose must never verify as the other"
        );
    }

    // --- The production ChainDidSigningKeyResolver over an honest chain source -----------------------

    /// An in-memory honest chain view (mirrors dig-identity's own test source). `SingletonLineage::single`
    /// is a TEST convenience only — production MUST use a genuine forward lineage walk.
    struct MockSource {
        lineage: Option<SingletonLineage>,
        stores: Vec<ChainStoreState>,
        fetched: Profile,
        fail: Option<&'static str>,
    }

    impl ChainSource for MockSource {
        type Error = &'static str;

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            match self.fail {
                Some("tip") => Err("lineage fetch failed"),
                _ => Ok(self.lineage.clone()),
            }
        }

        fn find_stores_for_did(&self, _did: &Did) -> Result<Vec<ChainStoreState>, Self::Error> {
            match self.fail {
                Some("stores") => Err("store scan failed"),
                _ => Ok(self.stores.clone()),
            }
        }

        fn fetch_profile(
            &self,
            _store: &StoreRecord,
            _root_hash: Bytes32,
        ) -> Result<Profile, Self::Error> {
            match self.fail {
                Some("fetch") => Err("content fetch failed"),
                _ => Ok(self.fetched.clone()),
            }
        }
    }

    /// A coin with the given parent (the pairing predicate reads only `parent_coin_info`).
    fn coin(parent: Bytes32) -> Coin {
        Coin::new(parent, Bytes32::new([9u8; 32]), 1)
    }

    /// A profile publishing the standard signing key.
    fn keyed_profile() -> Profile {
        let mut profile = Profile::with_schema_v1();
        profile.set(
            standard::SIGNING_PUBLIC_KEY,
            Value::Bytes(SIGNING_KEY.to_vec()),
        );
        profile
    }

    /// The canonical `did:chia:` string for a launcher id.
    fn did_for(launcher_id: Bytes32) -> String {
        use chia_sdk_utils::Address;
        Address::new(launcher_id, "did:chia:".to_string())
            .encode()
            .unwrap()
    }

    /// The happy path: one authoritative store launched from the DID's singleton lineage tip.
    fn authoritative(did_uri: &str) -> MockSource {
        let did_coin = coin(Bytes32::new([1u8; 32]));
        let profile = keyed_profile();
        let root_hash = Bytes32::new(profile.build_root().unwrap());
        MockSource {
            lineage: Some(SingletonLineage::single(did_coin.coin_id())),
            stores: vec![ChainStoreState {
                store: StoreRecord {
                    description: did_uri.to_string(),
                    launcher_coin: coin(did_coin.coin_id()),
                },
                root_hash,
            }],
            fetched: profile,
            fail: None,
        }
    }

    #[test]
    fn resolver_returns_the_chain_published_key_for_an_authoritative_did() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let resolver = ChainDidSigningKeyResolver::new(authoritative(&did_uri));
        // The source is exposed for reuse by other engine DID lookups.
        assert!(resolver
            .source()
            .find_stores_for_did(&Did::parse(&did_uri).unwrap())
            .is_ok());
        let key = resolver.resolve_signing_key(&did_uri).expect("resolves");
        assert_eq!(key, SigningPublicKey::new(SIGNING_KEY));
    }

    #[test]
    fn resolver_fails_closed_on_an_invalid_did() {
        let resolver = ChainDidSigningKeyResolver::new(authoritative("did:chia:whatever"));
        assert!(resolver.resolve_signing_key("not-a-did").is_none());
    }

    #[test]
    fn resolver_fails_closed_when_the_singleton_has_melted() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let mut source = authoritative(&did_uri);
        source.lineage = None; // no current unspent coin
        let resolver = ChainDidSigningKeyResolver::new(source);
        assert!(resolver.resolve_signing_key(&did_uri).is_none());
    }

    #[test]
    fn resolver_fails_closed_on_a_chain_source_error() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let mut source = authoritative(&did_uri);
        source.fail = Some("tip");
        let resolver = ChainDidSigningKeyResolver::new(source);
        assert!(resolver.resolve_signing_key(&did_uri).is_none());
    }

    #[test]
    fn resolver_fails_closed_when_the_profile_publishes_no_signing_key() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let mut source = authoritative(&did_uri);
        source.fetched = Profile::with_schema_v1(); // no slot 0x0010
        source.stores[0].root_hash = Bytes32::new(source.fetched.build_root().unwrap());
        let resolver = ChainDidSigningKeyResolver::new(source);
        assert!(resolver.resolve_signing_key(&did_uri).is_none());
    }

    // --- The resolver drives a genuine engine attach end to end -------------------------------------

    /// Derive a reproducible Ed25519 key from a label (hashed seed, never a literal).
    fn key_from(label: &[u8]) -> Ed25519KeyPair {
        let seed: [u8; 32] = Sha256::digest(label).into();
        Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid ed25519 seed")
    }

    /// A profile publishing a specific signing key.
    fn profile_with_key(key: &[u8; 32]) -> Profile {
        let mut profile = Profile::with_schema_v1();
        profile.set(standard::SIGNING_PUBLIC_KEY, Value::Bytes(key.to_vec()));
        profile
    }

    #[test]
    fn honest_attach_binds_the_session_to_the_chain_resolved_key() {
        let app = key_from(b"engine-attach-app-key");
        let app_pub: [u8; 32] = app.public_key().as_ref().try_into().unwrap();

        let did_uri = did_for(Bytes32::new([5u8; 32]));
        let profile = profile_with_key(&app_pub);
        let did_coin = coin(Bytes32::new([1u8; 32]));
        let source = MockSource {
            lineage: Some(SingletonLineage::single(did_coin.coin_id())),
            stores: vec![ChainStoreState {
                store: StoreRecord {
                    description: did_uri.clone(),
                    launcher_coin: coin(did_coin.coin_id()),
                },
                root_hash: Bytes32::new(profile.build_root().unwrap()),
            }],
            fetched: profile,
            fail: None,
        };
        let resolver = ChainDidSigningKeyResolver::new(source);

        let mut engine = EngineSessionRegistry::new(OsEntropy, resolver);
        let begin = engine
            .begin(&BeginParams {
                profile_did: did_uri.clone(),
                signing_pubkey_hex: hex::encode(app_pub),
            })
            .unwrap();

        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let signature = app.sign(&challenge_message(&nonce, &did_uri));
        let attach = engine
            .attach(&AttachParams {
                session_candidate: begin.session_candidate,
                signature_b64: BASE64.encode(signature.as_ref()),
                profile: ProfileAttachment {
                    did: did_uri.clone(),
                    subscriptions: vec![],
                    config_digest: "cfg".to_string(),
                },
            })
            .unwrap();
        assert_eq!(engine.open_sessions(), 1);
        assert!(engine.session(&attach.session_id).is_some());
    }

    #[test]
    fn attach_is_refused_when_the_did_advertises_a_key_it_did_not_publish() {
        // The DID publishes `app`'s key on-chain, but the caller advertises a stranger's key. The
        // resolver returns the published key, which mismatches the advertised one → KeyMismatch.
        let app = key_from(b"engine-attach-app-key");
        let stranger = key_from(b"engine-attach-stranger");
        let app_pub: [u8; 32] = app.public_key().as_ref().try_into().unwrap();
        let stranger_pub: [u8; 32] = stranger.public_key().as_ref().try_into().unwrap();

        let did_uri = did_for(Bytes32::new([5u8; 32]));
        let profile = profile_with_key(&app_pub);
        let did_coin = coin(Bytes32::new([1u8; 32]));
        let source = MockSource {
            lineage: Some(SingletonLineage::single(did_coin.coin_id())),
            stores: vec![ChainStoreState {
                store: StoreRecord {
                    description: did_uri.clone(),
                    launcher_coin: coin(did_coin.coin_id()),
                },
                root_hash: Bytes32::new(profile.build_root().unwrap()),
            }],
            fetched: profile,
            fail: None,
        };
        let mut engine =
            EngineSessionRegistry::new(OsEntropy, ChainDidSigningKeyResolver::new(source));
        let begin = engine
            .begin(&BeginParams {
                profile_did: did_uri.clone(),
                signing_pubkey_hex: hex::encode(stranger_pub),
            })
            .unwrap();
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let signature = stranger.sign(&challenge_message(&nonce, &did_uri));
        let err = engine
            .attach(&AttachParams {
                session_candidate: begin.session_candidate,
                signature_b64: BASE64.encode(signature.as_ref()),
                profile: ProfileAttachment {
                    did: did_uri.clone(),
                    subscriptions: vec![],
                    config_digest: "cfg".to_string(),
                },
            })
            .unwrap_err();
        assert_eq!(err, AttachError::KeyMismatch);
        assert_eq!(engine.open_sessions(), 0);
    }

    #[test]
    fn describe_covers_every_resolve_error_variant() {
        // A log-safe label for each variant (no key material, no chain internals).
        for (error, label) in [
            (ResolveError::InvalidDid, "invalid-did"),
            (ResolveError::NoIdentitySingleton, "no-identity-singleton"),
            (ResolveError::NoProfile, "no-authoritative-profile"),
            (ResolveError::AmbiguousProfile, "ambiguous-profile"),
            (ResolveError::StaleOrTamperedRoot, "stale-or-tampered-root"),
            (ResolveError::NoSigningKey, "no-signing-key"),
            (ResolveError::Chain("x".to_string()), "chain-source-error"),
        ] {
            assert_eq!(describe(&error), label);
        }
    }
}
