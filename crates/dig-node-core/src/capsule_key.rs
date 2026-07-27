//! [`CapsuleKey`] — the validated capsule identity every filesystem path and every log record on the
//! peer-facing surface is built from (#1599 / #1603 / #1609).
//!
//! # Why a type, and not a check
//!
//! A capsule is named by `(store_id, root)`, and on the peer surface BOTH components arrive as raw
//! bytes chosen by an untrusted caller. The node turns them into a path
//! (`<cache>/modules/<store>/<root>.module`) and into log records. Both are places where an
//! attacker-chosen string is dangerous: `..` segments walk out of the cache, and a `\n` forges a log
//! record.
//!
//! Those two hazards were previously held off by a `bool` predicate the caller had to remember to call.
//! That guard held on the availability path and was MISSING on the `dig.fetchRange` serve path — the
//! failure mode a per-call-site check always eventually has, because nothing about the code makes
//! forgetting it visible. Worse, the miss was not merely an arbitrary-read *attempt*: the blind serve
//! derives its decode key from the STORE id alone and never consults the root, so a traversal in the
//! ROOT component named an arbitrary file that then decoded and streamed normally.
//!
//! So the guard is a TYPE. [`CapsuleKey`] can only be constructed by [`CapsuleKey::parse`], which admits
//! nothing but two canonical 64-hex ids, and it is the only thing the path builders accept. A raw
//! `&str` pair can no longer reach a path join, so the class is unrepresentable rather than guarded:
//! there is no new call site that could reintroduce it, because there is no longer a function to call
//! incorrectly.
//!
//! # What canonical buys
//!
//! A 64-character ASCII-hex string contains no `/`, no `\`, no `.`, no `:`, no NUL and no control
//! character, so `join` on it can only ever produce a direct child of the directory it is joined to.
//! That is a property of the ALPHABET, not of a list of rejected patterns — which is why this is a
//! whitelist. A blacklist of `..`, absolute prefixes and UNC roots would have to be complete against
//! every platform's path grammar; the whitelist is complete by construction. The same property makes
//! the value safe to log verbatim: bounded at 64 characters, and control-character-free.
//!
//! Rejection is total and silent by design: a non-canonical key can never name content this node holds,
//! so the only honest answer is "not held", and it is given without touching the filesystem.

use std::fmt;
use std::path::{Path, PathBuf};

/// The number of hex digits in a canonical DIG content id (a 32-byte value).
const CANONICAL_ID_LEN: usize = 64;

/// The subdirectory whole-capsule pulls stage into, under the downloads directory.
///
/// Named once here because two things must agree on it and drift silently if they do not: the pull that
/// WRITES staging ([`CapsuleKey::staged_module_path`]) and the sweep that REAPS it
/// (`NodeContent::gc_once`). That disagreement is exactly the #1615 defect — the sweeper looked in the
/// parent directory while the pull staged in this one, so abandoned staging accumulated forever.
pub(crate) const MODULE_STAGING_SUBDIR: &str = "modules";

/// Is `s` a canonical DIG content id — a 32-byte value written as exactly 64 hex digits?
///
/// The single predicate every guard over a CALLER-SUPPLIED id shares, so "canonical" can never come to
/// mean two different things between the path guard and the log guard.
pub(crate) fn is_canonical_hex_id(s: &str) -> bool {
    s.len() == CANONICAL_ID_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A capsule identity — `(store_id, root)` — PROVEN to be two canonical 64-hex ids.
///
/// Holding one is the proof that a path built from it stays inside the directory it is joined to, and
/// that logging it can neither forge a record nor bloat one. Construct with [`CapsuleKey::parse`];
/// there is deliberately no other way in.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct CapsuleKey {
    store: String,
    root: String,
}

impl CapsuleKey {
    /// Validate a caller-supplied `(store, root)` pair, or `None` if either component is not a
    /// canonical 64-hex id.
    ///
    /// This is the ONLY boundary at which untrusted key bytes become a usable capsule identity, so it
    /// is the one place the whitelist has to be right.
    pub(crate) fn parse(store: &str, root: &str) -> Option<Self> {
        (is_canonical_hex_id(store) && is_canonical_hex_id(root)).then(|| CapsuleKey {
            store: store.to_string(),
            root: root.to_string(),
        })
    }

    /// The canonical store id.
    pub(crate) fn store(&self) -> &str {
        &self.store
    }

    /// The cached module path for this capsule: `<cache_dir>/modules/<store>/<root>.module`.
    ///
    /// The existence of this file is what makes the node a HOLDER of the capsule, so this is also the
    /// path the availability answer and the reshare promotion agree on.
    pub(crate) fn module_path(&self, cache_dir: &Path) -> PathBuf {
        cache_dir
            .join("modules")
            .join(&self.store)
            .join(format!("{}.module", self.root))
    }

    /// The staging path a whole-capsule warm pulls into: `<staging_dir>/modules/<store>-<root>.dig`.
    ///
    /// Deliberately NOT under the cache: a file at the cache path is already an announcement that this
    /// node holds the capsule, so an in-flight pull must not be visible there.
    pub(crate) fn staged_module_path(&self, staging_dir: &Path) -> PathBuf {
        staging_dir
            .join(MODULE_STAGING_SUBDIR)
            .join(format!("{}-{}.dig", self.store, self.root))
    }
}

/// Renders as `store:root` — the canonical capsule rendering used across the ecosystem, and safe in a
/// log record by construction (see the module docs).
impl fmt::Display for CapsuleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.store, self.root)
    }
}

/// Mirrors [`Display`](fmt::Display) rather than deriving, so a `{:?}` in a log or an error variant
/// cannot print a shape the `Display` guard was written to prevent. (Both are safe here — the fields
/// are canonical — but a derived `Debug` on a future non-canonical field would not be, and this keeps
/// the two renderings one decision.)
impl fmt::Debug for CapsuleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapsuleKey({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_id(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    /// Every key shape an untrusted caller could send that must NEVER become a `CapsuleKey`.
    ///
    /// Stated as the CLASS the whitelist excludes — non-hex alphabet and wrong length — rather than as
    /// a list of attacks, because the guard's correctness argument is about the alphabet: a rejected
    /// list would only ever be as complete as the imagination that wrote it.
    fn non_canonical_ids() -> Vec<String> {
        let canonical = hex_id(0xaa);
        vec![
            // Traversal, in each grammar a platform might honour.
            "..".to_string(),
            format!("../../{canonical}"),
            format!("..\\..\\{canonical}"),
            format!("/etc/{canonical}"),
            format!("C:\\Windows\\{canonical}"),
            format!("\\\\host\\share\\{canonical}"),
            format!("{canonical}/../{canonical}"),
            // Log injection + amplification.
            format!("{}\ninjected", &canonical[..54]),
            format!("{}\r\x1b[2J", &canonical[..58]),
            "z".repeat(64 * 1024),
            // Right alphabet, wrong length — the off-by-one either side of the bound.
            canonical[..63].to_string(),
            format!("{canonical}a"),
            String::new(),
            // Right length, wrong alphabet (the last character only).
            format!("{}!", &canonical[..63]),
            // Non-ASCII digits that a lenient parser might accept.
            format!("{}\u{ff41}", &canonical[..63]),
        ]
    }

    #[test]
    fn parse_admits_exactly_two_canonical_ids() {
        let (store, root) = (hex_id(0x7e), hex_id(0x9f));
        let key = CapsuleKey::parse(&store, &root).expect("two canonical ids are a capsule key");
        assert_eq!(key.store(), store);
        assert!(
            key.to_string().ends_with(&root),
            "the root is preserved verbatim"
        );
        // Mixed case is canonical hex: a caller must be able to name content in either casing.
        let mixed = format!("{}{}", "Ab".repeat(16), "cD".repeat(16));
        assert!(CapsuleKey::parse(&mixed, &mixed).is_some());
    }

    #[test]
    fn parse_rejects_a_non_canonical_id_in_either_position() {
        // BOTH positions, independently: the #1599 escape was in the ROOT component, which the
        // store-only reasoning ("the decode will fail anyway") did not cover — the blind serve derives
        // its key from the store id alone and never reads the root, so a root-component traversal
        // decodes and streams normally.
        let canonical = hex_id(0xaa);
        for hostile in non_canonical_ids() {
            assert!(
                CapsuleKey::parse(&hostile, &canonical).is_none(),
                "hostile store id must be rejected: {:?}",
                &hostile[..hostile.len().min(80)]
            );
            assert!(
                CapsuleKey::parse(&canonical, &hostile).is_none(),
                "hostile root must be rejected: {:?}",
                &hostile[..hostile.len().min(80)]
            );
        }
    }

    #[test]
    fn a_module_path_is_always_a_direct_child_of_the_stores_own_cache_directory() {
        // The property the type exists to guarantee, asserted against the real filesystem rather than
        // against the string: whatever the ids, the resolved path's parent is
        // `<cache>/modules/<store>` and the file is a direct child of it. `canonicalize` is what
        // collapses any `..`, so this would catch an escape that string inspection missed.
        let cache = tempfile::tempdir().expect("tempdir");
        let (store, root) = (hex_id(0x11), hex_id(0x22));
        let key = CapsuleKey::parse(&store, &root).expect("canonical");

        let path = key.module_path(cache.path());
        let parent = path.parent().expect("a module path has a parent");
        std::fs::create_dir_all(parent).expect("create the store dir");
        std::fs::write(&path, b"module").expect("write the module");

        let modules_root = cache
            .path()
            .join("modules")
            .canonicalize()
            .expect("modules");
        let resolved = path.canonicalize().expect("resolve the module path");
        assert!(
            resolved.starts_with(&modules_root),
            "{resolved:?} must stay under {modules_root:?}"
        );
        assert_eq!(
            resolved.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new(store.as_str())),
            "the module sits directly under its own store directory"
        );
    }

    #[test]
    fn staging_is_outside_the_cache_so_an_in_flight_pull_is_never_an_announcement() {
        let td = tempfile::tempdir().expect("tempdir");
        let (cache, staging) = (td.path().join("cache"), td.path().join("downloads"));
        let key = CapsuleKey::parse(&hex_id(0x33), &hex_id(0x44)).expect("canonical");
        assert!(!key.staged_module_path(&staging).starts_with(&cache));
    }

    #[test]
    fn a_key_renders_as_the_canonical_capsule_and_is_safe_to_log() {
        let (store, root) = (hex_id(0x5c), hex_id(0x6d));
        let key = CapsuleKey::parse(&store, &root).expect("canonical");
        let rendered = key.to_string();
        assert_eq!(rendered, format!("{store}:{root}"));
        // The two log hazards, checked on the rendering itself rather than trusted from the parse.
        assert!(
            !rendered.chars().any(char::is_control),
            "a rendered key can never end or forge a log record"
        );
        assert_eq!(rendered.len(), CANONICAL_ID_LEN * 2 + 1, "bounded length");
        assert_eq!(format!("{key:?}"), format!("CapsuleKey({rendered})"));
    }
}
