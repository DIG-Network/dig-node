//! The node's persistent mTLS machine identity — shared by every seam that dials or serves mTLS.
//!
//! Moved here unchanged from `peer.rs` (#1285 W1a): `load_or_generate_node_cert` is a pure
//! `(dir, seed) -> NodeCert` function with no coupling to the peer seam's `Node` state, and its
//! callers already span seam boundaries (the peer-network transport, the DHT bootstrap tests, and
//! the top-level `Node::peer_id_hex`) — exactly the "shared vocabulary" `shared/` exists for.

/// Install the process-wide rustls crypto provider (ring), idempotently. rustls 0.23 refuses to
/// auto-pick a provider when BOTH `ring` and `aws-lc-rs` are present in the dependency graph (aws-lc-rs
/// arrives transitively via chia-sdk-client), so any TLS use — the mTLS listener AND `dig_nat::connect`
/// — must have a provider installed FIRST or it panics. Call this once before bringing up the peer
/// network (and at the top of any test that dials/serves mTLS). A no-op if a provider is already set.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Load or mint the node's PERSISTENT, CA-signed [`NodeCert`](dig_tls::NodeCert) — its long-lived
/// machine mTLS identity for the peer network (#908 identity boundary, #1280).
///
/// The cert is signed by the shipped DigNetwork CA and BLS-bound (#1204) to the node's OWN identity
/// key, derived deterministically from the node's persistent 32-byte identity `seed` (the same seed
/// the legacy [`digstore_remote::identity::identity_from_seed`] consumes). The cert + private key are persisted under `dir`
/// (owner-only `0600`), so the node's `peer_id = SHA-256(SPKI DER)` is STABLE across restarts: the
/// first call mints + writes them, every later call loads the identical cert back.
///
/// This is the node's MACHINE identity, never a user key — the user's DID/wallet keys live in the
/// dig-app and never enter the node engine (NODE-1, #910). Unlike the self-signed
/// [`digstore_remote::identity::identity_from_seed`], this cert chains to the DigNetwork CA, so dig-nat's CA-signed mTLS peers
/// (#1280) accept it.
///
/// # Errors
/// Returns the stringified [`dig_tls::DigTlsError`] if the cert dir cannot be created/secured, or a
/// persisted cert fails to parse or chain to the CA.
pub fn load_or_generate_node_cert(
    dir: impl AsRef<std::path::Path>,
    seed: &[u8; 32],
) -> Result<std::sync::Arc<dig_tls::NodeCert>, String> {
    let bls_sk = dig_tls::bls::SecretKey::from_seed(seed);
    dig_tls::NodeCert::load_or_generate(dir, &bls_sk)
        .map(std::sync::Arc::new)
        .map_err(|e| format!("load or generate node cert: {e}"))
}
