//! Seam 7 — key management (#1285/#1303). Houses the [`KeyManager`] trait (the seam's public
//! surface — the node's MACHINE identity_seed/NodeCert lifecycle, carved unchanged from
//! `lib.rs`, #1285 W1b-6). The `dig-keystore` crate ADOPTION (the canonical keystore, #1024) is
//! the sealed at-rest half ([`machine_key`], dig_ecosystem#2168).
//!
//! **#908 boundary:** this seam is the machine-key/user-key boundary point. It NEVER holds a
//! user's DID/wallet signing key — see the module doc on [`key_manager::KeyManager`].

mod key_manager;
pub mod machine_key;

pub use key_manager::KeyManager;
pub use machine_key::{load_or_create_sealed_seed, MachineKeyError, MachineKeyStore};
