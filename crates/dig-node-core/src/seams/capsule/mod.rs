//! Seam 6 — capsule management (#1285/#1303). Houses the [`CapsuleStore`] trait (the seam's
//! public surface — list/remove/fetch/gap-fill/backfill the on-disk `.dig` capsule cache,
//! carved unchanged from `lib.rs`/`download.rs`, #1285 W1b-4). The concrete `.dig` format
//! reader/writer stays external (`digstore-core`); this seam is the NODE's cache-management
//! surface over it.

mod capsule_download;
mod capsule_store;
pub(crate) mod push_capsule;

pub use capsule_download::{download_capsule_via_rpc, CAPSULE_WINDOW_BYTES, MAX_CAPSULE_BYTES};
/// The inventory scan itself, so a test can drive the REAL disk-to-announce-set derivation rather
/// than a re-implementation of it.
#[cfg(test)]
pub(crate) use capsule_store::list_cached_capsules;
pub use capsule_store::CapsuleStore;
pub(crate) use push_capsule::{push_open_enabled, PUSH_CAPSULE_METHOD};
