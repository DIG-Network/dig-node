//! Dependency invariants asserted against this crate's own manifest and the workspace lock.
//!
//! Two classes of defect live here that no amount of unit testing can reach, because both are decided
//! by the BUILD rather than by any line of Rust:
//!
//! 1. **A fail-open bypass smuggled in by a feature flag.** The reshare path's chain-anchor gate is its
//!    only root of trust, and `dig-download` compiles a fail-OPEN verifier
//!    (`AcceptAnyModuleAnchor`) out of a default build specifically so a production wiring cannot name
//!    it. That protection is a Cargo feature, so it is defeated by editing a manifest — an edit that
//!    would compile, pass every test, and silently remove the guarantee.
//! 2. **A duplicated wire crate.** Two majors of a crate that defines a WIRE TYPE put two shapes either
//!    side of a trust boundary. Rust permits it happily; it presents as content that arrives and never
//!    verifies. That is the #836 `serde_bytes`-vs-base64 defect, which cost six blind diagnosis rounds,
//!    and #1576 hit its sibling on `ModuleInfo`.
//!
//! So both are asserted where they are actually decided: the manifest and the lock.

/// This crate's manifest, read at compile time so the assertion cannot drift from the build.
const MANIFEST_RAW: &str = include_str!("../Cargo.toml");

/// The manifest with its line endings normalised to `\n`.
///
/// An editor on Windows rewrites a manifest with CRLF without changing a single declaration.
/// Searching those bytes for `"\n[section]\n"` then finds nothing — which is a fact about the file's
/// line endings, not about its dependencies. dig-node#412 hit exactly that: a dependency-tier commit
/// saved this file as CRLF, and the section lookup below went on to report `dig-download` as absent
/// from a production tree it had never left. Normalising first keeps every assertion in this file
/// about DECLARATIONS, which is the only thing any of them means to be about.
fn manifest() -> &'static str {
    static NORMALISED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NORMALISED.get_or_init(|| MANIFEST_RAW.replace("\r\n", "\n"))
}

/// The workspace lock (two levels up from this crate).
const LOCK: &str = include_str!("../../../Cargo.lock");

/// The body of `section` in the manifest (up to the next `[` at column 0).
fn manifest_section(section: &str) -> &'static str {
    let manifest = manifest();
    // Panics rather than falling back to offset 0. A lookup that FAILED is not evidence about any
    // dependency, and offset 0 silently searches `[package]`, where nothing is declared — so every
    // "X is a production dependency" assertion below would then report absence with total
    // confidence. Failing here names the section that could not be read instead.
    let start = manifest
        .find(&format!("\n[{section}]\n"))
        .map(|i| i + section.len() + 4)
        .unwrap_or_else(|| panic!("this manifest has no `[{section}]` section to read"));
    let rest = &manifest[start..];
    let end = rest.find("\n[").unwrap_or(rest.len());
    &rest[..end]
}

/// **Proves:** the `testkit` feature — the flag that makes `dig_download::AcceptAnyModuleAnchor`, a
/// FAIL-OPEN module anchor verifier, nameable — is enabled ONLY for dev builds, never on the production
/// `dig-download` dependency.
///
/// **Catches:** the one-line manifest edit that would put a bypass of the reshare path's only root of
/// trust within reach of production code. Nothing else would notice: it compiles, and every existing
/// test still passes. Dev-dependency features do not propagate to consumers, so the node binaries never
/// see the flag — but only as long as it stays on the dev entry.
#[test]
fn the_fail_open_anchor_verifier_is_not_reachable_from_a_production_build() {
    let production = manifest_section("dependencies");
    let production_dig_download = production
        .lines()
        .find(|l| l.trim_start().starts_with("dig-download"))
        .expect("dig-download is a production dependency of this crate");
    assert!(
        !production_dig_download.contains("testkit"),
        "the production dig-download entry must NOT enable `testkit` — it is what makes the fail-OPEN \
         AcceptAnyModuleAnchor nameable, and the module pull's anchor gate is its only root of trust. \
         Found: {production_dig_download}"
    );

    // And it IS enabled for dev, so the harness the download tests need is actually available (a test
    // that only asserted absence would pass just as happily on a manifest missing both entries).
    assert!(
        manifest_section("dev-dependencies")
            .lines()
            .any(|l| l.trim_start().starts_with("dig-download") && l.contains("testkit")),
        "the dev-dependencies entry should enable `testkit` for the test harness"
    );
}

/// Every `version` recorded for `crate_name` in the workspace lock.
fn locked_versions(crate_name: &str) -> Vec<&str> {
    let needle = format!("name = \"{crate_name}\"");
    LOCK.split("[[package]]")
        .filter(|block| block.lines().any(|l| l.trim() == needle))
        .filter_map(|block| {
            block
                .lines()
                .find_map(|l| l.trim().strip_prefix("version = "))
                .map(|v| v.trim_matches('"'))
        })
        .collect()
}

/// **Proves:** exactly ONE `dig-rpc-protocol` resolves in the workspace, and it is the 0.10 line that
/// defines the module wire (`ModuleInfo` / `GetModuleInfoParams` / `FetchModuleRangeParams`) AND the
/// recursive-ask contract this node adopted (`GetAvailabilityParams::budget_ms` / `::ask_id`,
/// `AvailabilityAnswer::absence_established`, `ErrorCode::ContentMissInconclusive`).
///
/// **Catches:** the obligation-8 skew directly. Before the #1576 cascade, dig-download consumed
/// dig-rpc-protocol 0.5 while dig-peer 0.4 pulled 0.3.1, so a tree containing both held TWO `ModuleInfo`
/// types either side of the module pull's trust boundary — on `chunk_hashes`/`chunk_lens`, the fields
/// that drive the entire pull plan. Asserting the TRANSITIVE lock entry (not the caret dep in a manifest)
/// is the point: a consumer's own lock can pin an old patch even when every caret dep and every
/// higher-layer bump looks correct.
#[test]
fn the_workspace_carries_exactly_one_module_wire_crate() {
    let versions = locked_versions("dig-rpc-protocol");
    assert_eq!(
        versions.len(),
        1,
        "expected exactly one dig-rpc-protocol in the resolved workspace, found {versions:?} — two \
         majors means two `ModuleInfo` shapes across the module pull's trust boundary"
    );
    assert!(
        versions[0].starts_with("0.10."),
        "the availability contract this node adopted ships in dig-rpc-protocol 0.10; the workspace          resolved {} — on an earlier line the canonical items simply do not exist and this node          would be back to declaring its own",
        versions[0]
    );
}

/// **Proves:** exactly one `dig-peer` (the peer client the module transport dials through) and one
/// `dig-download` (the pull engine) resolve — so the node's own `ModuleTransport` and dig-download's
/// `NatRangeTransport` are talking through the SAME client, not two independent mTLS stacks.
#[test]
fn the_peer_client_and_pull_engine_are_not_duplicated() {
    // `dig-nat` and `dig-dht` are here for the same reason and it is not hypothetical: this node hands
    // its OWN `dig_nat` `NodeCert`/`NatConfig`/`NatRuntime` values INTO dig-download
    // (`NatRangeTransport::new_with_runtime`) and dig-gossip, so a second dig-nat instance is not a
    // size regression — those calls stop typechecking. Requesting the dig-nat 0.14 line while
    // dig-download 0.11 and dig-gossip 0.16 sit on ^0.13 resolves THREE dig-nat instances, which is
    // what this assertion exists to catch before a manifest edit ships (#1668).
    //
    // `dig-peer-selector` joined the list after the #1674 cascade, where it was the one member left on
    // the old line and so the sole source of a duplicate dig-nat AND dig-dht. It belongs here on the
    // same rule as the rest — the node bridges dig-download's `SourceSelector` to it
    // (`seams/dig_peer/selector_adapter.rs`), so its `dig-dht` candidate types must be the node's.
    for crate_name in [
        "dig-peer",
        "dig-download",
        "dig-nat",
        "dig-tls",
        "dig-dht",
        "dig-peer-selector",
    ] {
        let versions = locked_versions(crate_name);
        assert_eq!(
            versions.len(),
            1,
            "expected exactly one {crate_name} in the resolved workspace, found {versions:?}"
        );
    }
}

/// A `major.minor.patch` triple, ordered, so a version can be compared against a FLOOR rather than
/// checked for equality against one known-bad release.
fn semver_triple(version: &str) -> (u64, u64, u64) {
    let mut parts = version
        .split(['-', '+'])
        .next()
        .unwrap_or(version)
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

/// The release in which `dig-constants` replaced its PLACEHOLDER DIG L2 genesis challenge with the
/// real one. Every copy at or above this floor agrees on the chain identity; every copy below it does
/// not. See the assertion below for why this is a floor and not an equality check.
const REAL_GENESIS_FLOOR: (u64, u64, u64) = (0, 4, 0);

/// **Proves:** no `dig-constants` copy in the resolved workspace predates the real DIG L2 genesis
/// challenge — that is, every copy is at or above 0.4.0.
///
/// **Catches:** a dependency edit that pulls a pre-0.4.0 `dig-constants` back into the tree. That is
/// not hypothetical — it is the state this test was written to close (#2072). `dig-constants` 0.1.0
/// shipped an all-zeros PLACEHOLDER `DIG_MAINNET_GENESIS_CHALLENGE`, and it reached production through
/// `dig-clvm` 0.1.1, whose requirement `>=0.1.0, <0.2.0` could never resolve forward off it. So
/// `dig-wallet`'s spend-validation `ValidationContext` described a different chain identity than the
/// rest of the node. 0.4.0 finalized the real value (`0af98186…`, the header hash of DIG L2 block
/// 9021277) and recomputed all six AGG_SIG additional-data domains from it.
///
/// **Why the lock and not a source assertion.** No line of Rust pins the genesis literal, and none
/// should: every runtime check reads `dig_constants::DIG_MAINNET.genesis_challenge()` on BOTH sides of
/// its comparison, which is circular — it passes identically under the real value and under the
/// placeholder. The defect was therefore invisible to the entire suite, before the fix and after it.
/// It is decided by the BUILD, so it is asserted where it is decided.
///
/// **Why a FLOOR and not `!= "0.1.0"`.** The property is "no copy predating the real genesis", not
/// "not that one bad release" — an equality check is bypassed by the next pre-0.4.0 version to appear
/// (0.2.x and 0.3.x carry the same placeholder). This is the same rule the release gate enforces as
/// its 0.4.0 floor; one property, asserted at two levels.
#[test]
fn no_dig_constants_copy_predates_the_real_genesis_challenge() {
    let versions = locked_versions("dig-constants");

    // Without this the assertion below is vacuous: a lock with no dig-constants at all — a rename, a
    // vendoring, a botched merge — would satisfy an "every copy is current" claim while proving nothing.
    assert!(
        !versions.is_empty(),
        "the workspace must resolve dig-constants; finding none means this assertion has stopped \
         guarding anything"
    );

    let below_floor: Vec<&&str> = versions
        .iter()
        .filter(|v| semver_triple(v) < REAL_GENESIS_FLOOR)
        .collect();
    assert!(
        below_floor.is_empty(),
        "dig-constants {below_floor:?} predates 0.4.0, the release that replaced the PLACEHOLDER DIG \
         L2 genesis challenge with the real one. A copy below that floor puts a different chain \
         identity — and six differently-derived AGG_SIG domains — inside this binary. Find the holder \
         with `cargo tree -i dig-constants@<version>` and bump it; the resolved set was {versions:?}"
    );
}
