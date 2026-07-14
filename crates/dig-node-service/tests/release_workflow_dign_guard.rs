//! Guard: the reusable build workflow MUST build + publish the `dign` first-class alias
//! (issue #548) alongside `dig-node`, so every dig-node GitHub Release carries a
//! `dign-<ver>-<os_arch>[.exe]` asset with the SAME shape as `dig-node-<ver>-<os_arch>`.
//!
//! This is the producer-side counterpart to the dig-installer's `Repo::dign()` asset
//! matcher (a separate follow-up, #548 step 3): here we assert the workflow actually
//! EMITS the asset the installer will later resolve. The cross-OS build moved out of
//! `release.yml` into the reusable `build-binaries.yml` (#592, so the stable + nightly
//! channels share ONE build); this guard follows it there. The workflow is embedded at
//! compile time so the check runs hermetically with no filesystem access.

/// The reusable build workflow, embedded from the repo root (`crates/dig-node-service/tests`
/// is three levels below it).
const BUILD_YML: &str = include_str!("../../../.github/workflows/build-binaries.yml");

/// The build step must compile the `dign` bin target beside `dig-node`; dropping
/// `--bin dign` would silently stop shipping the alias.
#[test]
fn release_workflow_builds_the_dign_bin() {
    assert!(
        BUILD_YML.contains("--bin dig-node --bin dign"),
        "build-binaries.yml must `cargo build … --bin dig-node --bin dign`"
    );
}

/// The stage step must publish the alias under the `dign-<ver>-<os_arch>` stem — the
/// exact shape the dig-installer resolves (matching `dig-node-<ver>-<os_arch>`).
#[test]
fn release_workflow_stages_the_dign_asset() {
    assert!(
        BUILD_YML.contains("dist/dign-${VER}-${{ matrix.out_name }}"),
        "build-binaries.yml must stage a `dign-<ver>-<os_arch>` release asset"
    );
}
