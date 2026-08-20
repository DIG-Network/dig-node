//! Persisted per-store cache-tier tag — the on-disk memory that lets tier-aware modules-cache
//! eviction survive a node restart (#2015).
//!
//! The live eviction sweep ([`crate::Node::evict_modules_if_needed`]) sacrifices a `Tier0Precache`
//! module before a `Tier1Demand` one, reading each store's tier from TWO in-memory ledgers — the
//! inbound-demand ledger ([`crate::inbound_demand`]) and the tier-0 land ledger
//! ([`crate::tier0_live`]). Both are process-lifetime, so after a restart every on-disk module is
//! untagged and the sweep falls back to pure mtime-LRU, LOSING the tier-0-sacrifice-first precedence
//! until content is re-precached.
//!
//! This module persists the tier alongside the module bytes so that precedence is restored the moment
//! the node comes back up. The tag is a tiny **per-store sidecar** — `<cache>/modules/<store>/.tier` —
//! written ATOMICALLY (temp + rename, [`crate::write_atomic`]) whenever a store is landed or
//! tier-stamped, and read as a THIRD MAX source by [`crate::Node::module_tier`].
//!
//! # Why per-store, not per-module
//!
//! The tier is a property of the STORE (both in-memory ledgers key on `store_hex`, and
//! [`crate::Node::module_tier`] takes only `store_hex`). One sidecar per store dir therefore matches
//! the tier's granularity exactly, needs no per-root fan-out on write, and — being a single small
//! file rewritten atomically — has none of the read-modify-write race an index shared across stores
//! would carry.
//!
//! # Fail-safe by construction
//!
//! A store with NO sidecar (a legacy cache written before this shipped) or a malformed/unreadable one
//! reads back as `None`, which [`crate::Node::module_tier`] folds into its `Tier1Demand` default —
//! the PROTECTED tier. So a missing or corrupt tag can never cause genuinely-demanded content to be
//! wrongly evicted as if it were sacrificial tier-0; the worst case is that a precached store is
//! momentarily treated as demand until the next sweep re-stamps it.
//!
//! # Not part of the `.dig` format (§5.1)
//!
//! The sidecar is SEPARATE metadata, never a section of the capsule, so this adds nothing to and
//! breaks nothing in the on-chain-anchored `.dig` artifact — an older reader ignores the extra file
//! entirely.

use std::path::{Path, PathBuf};

use dig_sex::CacheTier;

/// The sidecar file name that holds a store's persisted [`CacheTier`]. A leading dot marks it as
/// metadata, and its lack of a capsule extension keeps [`crate::capsule_key::cached_root_stem`] from
/// ever mistaking it for a module — the eviction scan skips it for free.
const TIER_TAG_FILE: &str = ".tier";

/// The on-disk stable token for a tier. Chosen over the numeric [`CacheTier::rank`] so the file is
/// human-legible and a future rank renumbering cannot silently repoint an existing tag.
fn tier_token(tier: CacheTier) -> &'static str {
    match tier {
        CacheTier::Tier0Precache => "tier0",
        CacheTier::Tier1Demand => "tier1",
        CacheTier::Tier2Bribed => "tier2",
    }
}

/// Parse a persisted token back into a [`CacheTier`], or `None` for anything unrecognised — the
/// fail-safe path a truncated/garbage sidecar takes. Whitespace-tolerant so a trailing newline a
/// human or editor added does not defeat the read.
fn parse_tier_token(raw: &str) -> Option<CacheTier> {
    match raw.trim() {
        "tier0" => Some(CacheTier::Tier0Precache),
        "tier1" => Some(CacheTier::Tier1Demand),
        "tier2" => Some(CacheTier::Tier2Bribed),
        _ => None,
    }
}

/// The sidecar path for `store_hex`: `<cache_dir>/modules/<store_hex>/.tier`.
fn tier_tag_path(cache_dir: &Path, store_hex: &str) -> PathBuf {
    cache_dir
        .join("modules")
        .join(store_hex)
        .join(TIER_TAG_FILE)
}

/// Persist `tier` for `store_hex` ONLY when that store already has a module directory on disk.
///
/// Guarding on the existing directory keeps a demand event for a not-yet-cached store from creating an
/// orphan `<store>/.tier` with no module beside it. Where the caller already holds the store dir open
/// (the eviction sweep), use [`write_tier_tag`] directly. Best-effort: a write failure is swallowed —
/// a missing tag simply fails safe to the protected default on the next read.
pub(crate) fn write_tier_tag_if_cached(cache_dir: &Path, store_hex: &str, tier: CacheTier) {
    let store_dir = cache_dir.join("modules").join(store_hex);
    if store_dir.is_dir() {
        write_tier_tag(cache_dir, store_hex, tier);
    }
}

/// Atomically persist `tier` as `store_hex`'s sidecar. Best-effort (see [`write_tier_tag_if_cached`]).
pub(crate) fn write_tier_tag(cache_dir: &Path, store_hex: &str, tier: CacheTier) {
    let _ = crate::write_atomic(
        &tier_tag_path(cache_dir, store_hex),
        tier_token(tier).as_bytes(),
    );
}

/// Read `store_hex`'s persisted tier, or `None` when there is no sidecar or it is unreadable/malformed
/// — the fail-safe default (the caller folds `None` into `Tier1Demand`, the protected tier).
#[must_use]
pub(crate) fn read_tier_tag(cache_dir: &Path, store_hex: &str) -> Option<CacheTier> {
    let raw = std::fs::read_to_string(tier_tag_path(cache_dir, store_hex)).ok()?;
    parse_tier_token(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_round_trips_every_tier() {
        let td = tempfile::tempdir().unwrap();
        let store = "ab".repeat(32);
        // The store dir must exist for the guarded write to fire.
        std::fs::create_dir_all(td.path().join("modules").join(&store)).unwrap();
        for tier in [
            CacheTier::Tier0Precache,
            CacheTier::Tier1Demand,
            CacheTier::Tier2Bribed,
        ] {
            write_tier_tag(td.path(), &store, tier);
            assert_eq!(read_tier_tag(td.path(), &store), Some(tier));
        }
    }

    #[test]
    fn a_missing_sidecar_reads_as_none() {
        let td = tempfile::tempdir().unwrap();
        assert_eq!(read_tier_tag(td.path(), &"cd".repeat(32)), None);
    }

    #[test]
    fn a_malformed_sidecar_reads_as_none_and_never_panics() {
        let td = tempfile::tempdir().unwrap();
        let store = "ef".repeat(32);
        let path = tier_tag_path(td.path(), &store);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"\x00garbage-not-a-tier\xff").unwrap();
        assert_eq!(read_tier_tag(td.path(), &store), None);
    }

    #[test]
    fn the_guarded_write_skips_a_store_with_no_module_dir() {
        let td = tempfile::tempdir().unwrap();
        let store = "12".repeat(32);
        // No <modules>/<store> dir yet → the guarded write must NOT create an orphan tag.
        write_tier_tag_if_cached(td.path(), &store, CacheTier::Tier0Precache);
        assert_eq!(read_tier_tag(td.path(), &store), None);
        assert!(!td.path().join("modules").join(&store).exists());
    }

    #[test]
    fn a_trailing_newline_is_tolerated() {
        assert_eq!(parse_tier_token("tier0\n"), Some(CacheTier::Tier0Precache));
        assert_eq!(parse_tier_token("  tier2  "), Some(CacheTier::Tier2Bribed));
    }
}
