//! Seam 7's public surface (#1285/#1303) — the node's MACHINE-key lifecycle: the persistent
//! §21.9 identity seed, the derived stable mTLS `peer_id`, and the on-disk cert directories the
//! L7 peer network's [`dig_nat::NodeCert`] lives under.
//!
//! **#908 boundary (foundational, preserved exactly by this carve):** this seam holds ONLY the
//! node's own MACHINE identity — never a user's DID/wallet signing key. A dig-app proves
//! possession of a profile's identity key over the IPC session (`crate::session`); that key never
//! crosses into the engine. `KeyManager` does not add, and must never grow, a user-key path.
//!
//! `KeyManager` is implemented by [`Node`] with the EXISTING method bodies (carved unchanged
//! from `lib.rs`, #1285 W1b-6) — a behaviour-preserving trait extraction, not a new
//! implementation, and NOT a `dig-keystore` crate adoption (a later wave, coordinated with the
//! key-management family). Plain `Send + Sync` (no async methods) but kept trait-shaped to match
//! the other seams' pattern, so it stays dyn-compatible for the future `Arc<dyn KeyManager>`
//! handle (W1c).

use std::path::PathBuf;

use crate::Node;

/// Seam 7 (key management) — the node's machine identity_seed/NodeCert lifecycle. See the module
/// doc for the #908 boundary this seam enforces.
pub trait KeyManager: Send + Sync {
    /// The node's own `peer_id` (64-hex) = SHA-256(SPKI DER) of its PERSISTENT, CA-signed
    /// [`NodeCert`](dig_nat::NodeCert), or `None` if no identity seed is configured. This is the mTLS
    /// identity the node presents on every peer path (loaded from — or minted into — the node's cert
    /// dir, so it is stable across restarts; see [`crate::peer::load_or_generate_node_cert`]).
    fn peer_id_hex(&self) -> Option<String>;

    /// The node's persistent identity seed, if configured — the source of the STABLE mTLS `peer_id`
    /// for the L7 peer network (see [`crate::peer::load_or_generate_node_cert`]). `None` disables the
    /// peer network (the node still serves the HTTP read path).
    fn identity_seed_for_peer(&self) -> Option<[u8; 32]>;

    /// The directory the L7 peer network keeps its TLS cert/key + peer address book under (a
    /// `peer-net/` subdir of the cache dir, so it shares the node's data root + writability handling).
    fn peer_cert_dir(&self) -> PathBuf;

    /// The directory the node's PERSISTENT, CA-signed [`NodeCert`](dig_nat::NodeCert) identity
    /// (`node.crt` + `node.key`, 0600) lives under — an `identity/` subdir of [`Self::peer_cert_dir`],
    /// kept SEPARATE from dig-gossip's own `node.key` in `peer-net/` so the two never clobber each
    /// other. This is the node's stable machine transport identity (#908, #1280); its `peer_id`
    /// survives restarts because the cert is loaded back from here.
    fn node_cert_dir(&self) -> PathBuf;
}

impl KeyManager for Node {
    fn peer_id_hex(&self) -> Option<String> {
        let seed = self.identity_seed?;
        crate::peer::load_or_generate_node_cert(self.node_cert_dir(), &seed)
            .ok()
            .map(|cert| cert.peer_id().to_hex())
    }

    fn identity_seed_for_peer(&self) -> Option<[u8; 32]> {
        self.identity_seed
    }

    fn peer_cert_dir(&self) -> PathBuf {
        self.cache_dir.join("peer-net")
    }

    fn node_cert_dir(&self) -> PathBuf {
        self.peer_cert_dir().join("identity")
    }
}
