//! Guard: the reusable build workflow MUST build + publish the `dign` first-class alias
//! (issue #548) alongside `dig-node`, so every dig-node GitHub Release carries a
//! `dign-<ver>-<os_arch>[.exe]` asset with the SAME shape as `dig-node-<ver>-<os_arch>`.
//!
//! This is the producer-side counterpart to the dig-installer's `Repo::dign()` asset
//! matcher (a separate follow-up, #548 step 3): here we assert the workflow actually
//! EMITS the asset the installer will later resolve. The cross-OS build moved out of
//! `release.yml` into the reusable `build-binaries.yml` (#592, so the stable + nightly
//! channels share ONE build), and the ASSET NAMING then moved again, into the
//! `stage-binaries` composite action (dig_ecosystem#1736: the Linux targets had to move
//! into a pinned old-glibc container, giving two build jobs that must not be able to
//! diverge on the names they publish). This guard follows the naming to its current home.
//! Both files are embedded at compile time so the check runs hermetically.

/// The reusable build workflow, embedded from the repo root (`crates/dig-node-service/tests`
/// is three levels below it).
const BUILD_YML: &str = include_str!("../../../.github/workflows/build-binaries.yml");

/// The composite action that OWNS the published asset names for every platform.
const STAGE_ACTION_YML: &str = include_str!("../../../.github/actions/stage-binaries/action.yml");

/// Every build job must compile the `dign` bin target beside `dig-node`; dropping
/// `--bin dign` would silently stop shipping the alias.
///
/// The COUNT is asserted, not just the presence: there are now TWO build jobs (the
/// Windows/macOS host-runner matrix and the containerized Linux matrix), and a guard that
/// accepted one occurrence would not notice one of them dropping the alias.
#[test]
fn every_build_job_builds_the_dign_bin() {
    let jobs_building_dign = BUILD_YML.matches("--bin dig-node --bin dign").count();
    assert_eq!(
        jobs_building_dign, 2,
        "both build jobs (host-runner + containerized Linux) must \
         `cargo build … --bin dig-node --bin dign`; found {jobs_building_dign}"
    );
}

/// The staging action must publish BOTH stems under `<stem>-<ver>-<os_arch>` — the exact
/// shape the dig-installer resolves.
#[test]
fn the_staging_action_publishes_both_the_dig_node_and_dign_stems() {
    assert!(
        STAGE_ACTION_YML.contains("for stem in dig-node dign"),
        "stage-binaries must stage BOTH the `dig-node` binary and the `dign` alias"
    );
    assert!(
        STAGE_ACTION_YML.contains(r#"cp "$src" "dist/${stem}-${VER}-${{ inputs.out-name }}""#),
        "stage-binaries must publish each stem as `<stem>-<ver>-<os_arch>`"
    );
}

/// Naming lives in ONE place. If a build job ever stages an asset itself, the two jobs can
/// drift on the names downstream consumers resolve — precisely the failure the composite
/// action was extracted to prevent.
#[test]
fn no_build_job_stages_assets_outside_the_staging_action() {
    assert!(
        !BUILD_YML.contains("dist/dig-node-${VER}") && !BUILD_YML.contains("dist/dign-${VER}"),
        "build-binaries.yml must delegate asset naming to ./.github/actions/stage-binaries, \
         never construct an asset name itself"
    );
    assert!(
        BUILD_YML
            .matches("./.github/actions/stage-binaries")
            .count()
            >= 2,
        "every build job must stage through the shared action"
    );
}

/// Guard (#585): the release NO LONGER ships the duplicate legacy `dig-companion-*`
/// asset. dig-node was formerly dig-companion (#209); the old dual-naming published a
/// byte-identical copy of every binary under a `dig-companion-<ver>-<os_arch>` name. No
/// downstream consumer resolves that legacy name from a dig-node RELEASE:
///   * apt.dig.net's packaging uses the canonical `dig-node-{ver}-linux-{arch}` template,
///   * the dig-installer's legacy fallback targets the SEPARATE `DIG-Network/dig-companion`
///     repo's own frozen historical releases (its own asset stem), not this asset name.
///
/// So the duplicate is pure release-noise — the build must ship ONLY `dig-node-*` + `dign-*`.
/// Checked in BOTH files, since either could reintroduce the copy.
#[test]
fn release_workflow_no_longer_ships_the_legacy_dig_companion_asset() {
    // Scope to the STAGED asset path (`dist/dig-companion-…`), not any mention of the word —
    // the header comments legitimately explain WHY the legacy copy was dropped.
    for (name, yml) in [
        ("build-binaries.yml", BUILD_YML),
        ("stage-binaries/action.yml", STAGE_ACTION_YML),
    ] {
        assert!(
            !yml.contains("dist/dig-companion"),
            "{name} must NOT stage a duplicate legacy `dig-companion-*` asset \
             (#585) — ship only the canonical `dig-node-*` name + the `dign-*` alias"
        );
    }
}
