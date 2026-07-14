//! Guard: the release workflow MUST build + publish the `dign` first-class alias
//! (issue #548) alongside `dig-node`, so every dig-node GitHub Release carries a
//! `dign-<ver>-<os_arch>[.exe]` asset with the SAME shape as `dig-node-<ver>-<os_arch>`.
//!
//! This is the producer-side counterpart to the dig-installer's `Repo::dign()` asset
//! matcher (a separate follow-up, #548 step 3): here we assert the workflow actually
//! EMITS the asset the installer will later resolve. `release.yml` is embedded at
//! compile time so the check runs hermetically with no filesystem access.

/// The release workflow, embedded from the repo root (`crates/dig-node-service/tests`
/// is three levels below it).
const RELEASE_YML: &str = include_str!("../../../.github/workflows/release.yml");

/// The build step must compile the `dign` bin target beside `dig-node`; dropping
/// `--bin dign` would silently stop shipping the alias.
#[test]
fn release_workflow_builds_the_dign_bin() {
    assert!(
        RELEASE_YML.contains("--bin dig-node --bin dign"),
        "release.yml must `cargo build … --bin dig-node --bin dign`"
    );
}

/// The stage step must publish the alias under the `dign-<ver>-<os_arch>` stem — the
/// exact shape the dig-installer resolves (matching `dig-node-<ver>-<os_arch>`).
#[test]
fn release_workflow_stages_the_dign_asset() {
    assert!(
        RELEASE_YML.contains("dist/dign-${VER}-${{ matrix.out_name }}"),
        "release.yml must stage a `dign-<ver>-<os_arch>` release asset"
    );
}
