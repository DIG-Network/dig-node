//! [`CapsuleKey`] — the validated capsule identity every filesystem path and every log record on the
//! peer-facing surface is built from (#1599 / #1603 / #1609).
//!
//! # Why a type, and not a check
//!
//! A capsule is named by `(store_id, root)`, and on the peer surface BOTH components arrive as raw
//! bytes chosen by an untrusted caller. The node turns them into a path
//! (`<cache>/modules/<store>/<root>.dig`) and into log records. Both are places where an
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

/// The file extension a freshly-landed capsule is written with (#1896).
///
/// Unified with the staging artifact ([`CapsuleKey::staged_module_path`], `.dig`) so ONE capsule has
/// ONE artifact extension end-to-end — a cached capsule and the `.dig` it was staged from are now the
/// same shape, not `.module` vs `.dig`.
pub(crate) const CACHED_MODULE_EXT: &str = "dig";

/// The extension a PRIOR node version wrote a landed capsule with (#1896).
///
/// Still READ — reader-tolerance keeps a cache written by an older binary making this node a holder —
/// and a startup pass ([`migrate_legacy_module_extensions`]) renames it to [`CACHED_MODULE_EXT`], so
/// the fallback is only ever exercised on a not-yet-migrated cache.
pub(crate) const LEGACY_MODULE_EXT: &str = "module";

/// The extension of the sidecar that marks a cached capsule as RELAYED — held on a stranger's behalf,
/// never advertised (dig-node#276).
///
/// A SIDECAR rather than a field inside the capsule, because the capsule's bytes are content-addressed:
/// they are byte-identical whether this node pulled them for itself or for someone else, so the
/// distinction cannot live inside them. It sits beside the module as `<root>.relay`, which
/// [`cached_root_stem`] does not accept — so the marker is invisible to the inventory scan as a capsule
/// while being visible to it as a PROPERTY of one.
pub(crate) const RELAY_MARKER_EXT: &str = "relay";

/// The relay-marker sidecar that belongs beside the cached capsule at `module_path`.
///
/// Derived from the module path rather than from a [`CapsuleKey`] so the disk scan — which has a path
/// and no key — and the writer — which has a key and no scan — compute the SAME name from one authority.
/// Extension-independent: a legacy `.module` capsule and a current `.dig` one share the marker name, so
/// the #1896 migration can never orphan a suppression.
pub(crate) fn relay_marker_beside(module_path: &Path) -> Option<PathBuf> {
    let stem = cached_root_stem(module_path.file_name()?.to_str()?)?;
    Some(module_path.with_file_name(format!("{stem}.{RELAY_MARKER_EXT}")))
}

/// Delete the relay marker beside `module_path`, if there is one.
///
/// Called wherever a cached module is unlinked, so a marker can never outlive the capsule it describes.
/// An orphan marker would silently suppress the announce of a LATER, genuinely-held acquisition of the
/// same generation; binding the two lifetimes together makes that state unreachable rather than merely
/// unlikely. Best-effort: a failed unlink is not worth failing an eviction over.
pub(crate) fn discard_relay_marker_beside(module_path: &Path) {
    if let Some(marker) = relay_marker_beside(module_path) {
        let _ = std::fs::remove_file(marker);
    }
}

/// Strip the cached-capsule extension — the current `.dig` or the legacy `.module` (#1896) — from a
/// file name, yielding its `<root_hex>` stem, or `None` if the name is not a cached capsule.
///
/// The SINGLE authority on which suffixes name a capsule on disk, so the inventory scan
/// ([`CapsuleStore::cache_list_cached`](crate::CapsuleStore::cache_list_cached)) and the path builders
/// can never disagree about what counts as a held capsule.
pub(crate) fn cached_root_stem(file_name: &str) -> Option<&str> {
    file_name
        .strip_suffix(&format!(".{CACHED_MODULE_EXT}"))
        .or_else(|| file_name.strip_suffix(&format!(".{LEGACY_MODULE_EXT}")))
}

/// Converge a cache written by a prior binary onto the unified `.dig` artifact (#1896): rename every
/// legacy `<cache>/modules/<store>/*.module` to `*.dig`.
///
/// Idempotent + crash-safe by construction, so it is safe to run unconditionally at every bring-up:
/// - a name whose `.dig` target ALREADY exists has its redundant `.module` deleted (dedup, never a
///   failure), because the two are byte-identical content-addressed artifacts;
/// - a partially-migrated cache is finished by the next run, and reader-tolerance
///   ([`CapsuleKey::resolve_cached_path`]) serves either suffix in the meantime, so an interrupted
///   pass never drops a holder.
///
/// Best-effort: an unreadable directory or a failed rename is skipped rather than propagated — a
/// convergence sweep must never abort a node's bring-up.
pub(crate) fn migrate_legacy_module_extensions(cache_dir: &Path) {
    let modules_root = cache_dir.join("modules");
    let Ok(stores) = std::fs::read_dir(&modules_root) else {
        return; // no cache yet — nothing to converge
    };
    for store_entry in stores.flatten() {
        let store_dir = store_entry.path();
        if !store_dir.is_dir() {
            continue;
        }
        let Ok(modules) = std::fs::read_dir(&store_dir) else {
            continue;
        };
        for m in modules.flatten() {
            let legacy = m.path();
            let is_legacy = legacy
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == LEGACY_MODULE_EXT);
            if !is_legacy {
                continue;
            }
            let unified = legacy.with_extension(CACHED_MODULE_EXT);
            if unified.exists() {
                // Both artifacts present (a prior interrupted run, or a re-land): the `.dig` is the
                // canonical one, so the legacy duplicate is redundant — remove it rather than fail.
                let _ = std::fs::remove_file(&legacy);
            } else {
                let _ = std::fs::rename(&legacy, &unified);
            }
        }
    }
}

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

    /// This capsule as the identity the cache and advertisement layers decide over.
    ///
    /// Infallible by construction: [`parse`](Self::parse) already admitted nothing but two canonical
    /// 64-hex ids, so the decode below cannot fail — which is exactly why the conversion lives here
    /// and not at each call site, where it would have to invent a fallback for a case that cannot
    /// happen.
    pub(crate) fn identity(&self) -> dig_sex::CapsuleIdentity {
        let decode = |hex: &str| {
            crate::dht::hex64(hex)
                .expect("a CapsuleKey component is canonical 64-hex by construction")
        };
        dig_sex::CapsuleIdentity {
            store_id: decode(&self.store).into(),
            root_hash: decode(&self.root).into(),
        }
    }

    /// The cached module path for this capsule: `<cache_dir>/modules/<store>/<root>.dig` (#1896).
    ///
    /// The existence of this file is what makes the node a HOLDER of the capsule, so this is also the
    /// path a fresh land WRITES and the shape the availability answer and reshare promotion agree on.
    /// To READ a capsule (which may still be on disk under the legacy `.module` extension), go through
    /// [`resolve_cached_path`](Self::resolve_cached_path), not this — this always names the CURRENT
    /// `.dig` shape.
    pub(crate) fn module_path(&self, cache_dir: &Path) -> PathBuf {
        self.cached_path_with_ext(cache_dir, CACHED_MODULE_EXT)
    }

    /// The cached path for this capsule with an explicit extension — the shared join both the current
    /// `.dig` and the legacy `.module` paths are built from, so the directory layout lives in ONE place.
    fn cached_path_with_ext(&self, cache_dir: &Path, ext: &str) -> PathBuf {
        cache_dir
            .join("modules")
            .join(&self.store)
            .join(format!("{}.{ext}", self.root))
    }

    /// Resolve where this capsule ACTUALLY lives on disk to read it, tolerating a legacy cache (#1896):
    /// the current `.dig` path if it exists, else the legacy `.module` path a prior binary may have
    /// written, else the `.dig` path.
    ///
    /// Returning the `.dig` path when NEITHER exists is deliberate: a caller about to write, or about
    /// to report "not held", should see the canonical current shape, never the legacy one. Every read
    /// site routes through here so no site re-derives the fallback and drifts (#1896).
    pub(crate) fn resolve_cached_path(&self, cache_dir: &Path) -> PathBuf {
        let unified = self.module_path(cache_dir);
        if unified.exists() {
            return unified;
        }
        let legacy = self.cached_path_with_ext(cache_dir, LEGACY_MODULE_EXT);
        if legacy.exists() {
            return legacy;
        }
        unified
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

    #[test]
    fn a_landed_capsule_is_written_with_the_dig_extension() {
        // #1896: the cache landing is unified onto `.dig` — `module_path` (the WRITE path) names the
        // `.dig` artifact, never the legacy `.module`.
        let cache = tempfile::tempdir().expect("tempdir");
        let key = CapsuleKey::parse(&hex_id(0x11), &hex_id(0x22)).expect("canonical");
        let path = key.module_path(cache.path());
        assert_eq!(
            path.extension().and_then(|e| e.to_str()),
            Some("dig"),
            "a landed capsule is a `.dig`, not a `.module`"
        );
    }

    #[test]
    fn resolve_cached_path_prefers_dig_then_falls_back_to_legacy_module() {
        // #1896 reader-tolerance: read the current `.dig` when present, else the legacy `.module` a
        // prior binary wrote, else the canonical `.dig` shape (for a not-held / about-to-write caller).
        let cache = tempfile::tempdir().expect("tempdir");
        let key = CapsuleKey::parse(&hex_id(0x33), &hex_id(0x44)).expect("canonical");
        let dig = key.module_path(cache.path());
        let legacy = key.cached_path_with_ext(cache.path(), LEGACY_MODULE_EXT);
        std::fs::create_dir_all(dig.parent().unwrap()).unwrap();

        // Neither present → the canonical `.dig` shape.
        assert_eq!(key.resolve_cached_path(cache.path()), dig);

        // Only legacy present → the legacy path (a cache written by an older version is still served).
        std::fs::write(&legacy, b"legacy").unwrap();
        assert_eq!(key.resolve_cached_path(cache.path()), legacy);

        // Both present → the `.dig` wins (the canonical current artifact).
        std::fs::write(&dig, b"unified").unwrap();
        assert_eq!(key.resolve_cached_path(cache.path()), dig);
    }

    #[test]
    fn cached_root_stem_accepts_either_suffix_and_rejects_others() {
        let root = hex_id(0x55);
        assert_eq!(
            cached_root_stem(&format!("{root}.dig")),
            Some(root.as_str())
        );
        assert_eq!(
            cached_root_stem(&format!("{root}.module")),
            Some(root.as_str())
        );
        assert_eq!(cached_root_stem(&format!("{root}.tmp")), None);
        assert_eq!(cached_root_stem(&root), None);
    }

    #[test]
    fn startup_migration_renames_module_to_dig_and_is_idempotent() {
        // #1896 convergence: a startup pass renames legacy `.module` to `.dig`; where both already
        // exist the redundant `.module` is deleted; nothing is lost; a second run is a no-op.
        let cache = tempfile::tempdir().expect("tempdir");
        let store = hex_id(0x66);
        let store_dir = cache.path().join("modules").join(&store);
        std::fs::create_dir_all(&store_dir).unwrap();

        let root_legacy = hex_id(0x01);
        let root_both = hex_id(0x02);
        std::fs::write(store_dir.join(format!("{root_legacy}.module")), b"a").unwrap();
        // A capsule already migrated on a prior interrupted run: BOTH suffixes on disk.
        std::fs::write(store_dir.join(format!("{root_both}.module")), b"b").unwrap();
        std::fs::write(store_dir.join(format!("{root_both}.dig")), b"b").unwrap();

        migrate_legacy_module_extensions(cache.path());

        assert!(store_dir.join(format!("{root_legacy}.dig")).exists());
        assert!(!store_dir.join(format!("{root_legacy}.module")).exists());
        assert!(store_dir.join(format!("{root_both}.dig")).exists());
        assert!(
            !store_dir.join(format!("{root_both}.module")).exists(),
            "the redundant legacy duplicate is removed"
        );

        // Idempotent: a second run changes nothing.
        migrate_legacy_module_extensions(cache.path());
        let names: Vec<_> = std::fs::read_dir(&store_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "only the two `.dig` artifacts remain");
        assert!(names.iter().all(|n| n.ends_with(".dig")));
    }
}
