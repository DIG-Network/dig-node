//! Seam 7 — key management (#1285/#1303). Houses the [`KeyManager`] trait (the seam's public
//! surface — the node's MACHINE identity_seed/NodeCert lifecycle, carved unchanged from
//! `lib.rs`, #1285 W1b-6). The `dig-keystore` crate ADOPTION (the canonical keystore, #1024) is
//! a later wave, coordinated with the key-management family — out of scope here.
//!
//! **#908 boundary:** this seam is the machine-key/user-key boundary point. It NEVER holds a
//! user's DID/wallet signing key — see the module doc on [`key_manager::KeyManager`].

mod key_manager;

pub use key_manager::KeyManager;
