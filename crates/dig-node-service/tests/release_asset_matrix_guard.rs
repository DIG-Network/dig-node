//! Guard: the release-asset EXPECTATION cannot drift away from what the build actually
//! produces, and exactly one place may move `releases/latest` (dig-node#335).
//!
//! #335 shipped because a stable release became `latest` carrying four of its fourteen assets.
//! Two mechanisms now prevent that, and both of them are only as good as their resistance to
//! quiet drift:
//!
//!   1. `.github/actions/check-release-assets` holds a HAND-MAINTAINED platform list. Losing a
//!      platform from the build fails loudly — the guard demands an asset nobody produces. But
//!      GAINING one fails SILENTLY: a new leg enters the build matrix, the expectation stays at
//!      the old count, and a release missing the new platform's binaries passes every check and
//!      becomes `latest`. That is exactly the arm64 platform-floor class
//!      (dig_ecosystem#1741/#1736/#2126) that the expectation's own comment cites.
//!   2. Promotion belongs to `release.yml`'s `promote` job alone, after verification. A second
//!      promoter — an `action-gh-release` step drifting back to its `make_latest` DEFAULT of
//!      true, or a stray `gh release edit --latest` — restores #335 verbatim while every job
//!      still reports success.
//!
//! The self-test inside `verify-release-assets.yml` cannot catch either. It drives the guard over
//! LITERAL asset lists written from the same expectation, so it matches its own needle: a
//! platform absent from the expectation is equally absent from the fixture. Only a check that
//! reads the BUILD's matrix, rather than the expectation's restatement of it, can see the gap.
//!
//! Every file is embedded at compile time so these run hermetically.

/// Owns the expected asset set the release is verified against.
const CHECK_ACTION_YML: &str =
    include_str!("../../../.github/actions/check-release-assets/action.yml");

/// Owns the platform matrix the binaries are actually built for.
const BUILD_YML: &str = include_str!("../../../.github/workflows/build-binaries.yml");

/// The two publishers and the orchestrator — every workflow that can touch `latest`.
const RELEASE_YML: &str = include_str!("../../../.github/workflows/release.yml");
const PACKAGE_YML: &str = include_str!("../../../.github/workflows/package.yml");
const NIGHTLY_YML: &str = include_str!("../../../.github/workflows/nightly-release.yml");

/// The `PLATFORMS=(…)` array the expected asset names are generated from.
fn expected_platforms() -> Vec<String> {
    let (_, after) = CHECK_ACTION_YML
        .split_once("PLATFORMS=(")
        .expect("check-release-assets must declare a `PLATFORMS=(…)` array");
    let (inner, _) = after
        .split_once(')')
        .expect("the `PLATFORMS=(` array must be closed on one line");
    let mut platforms: Vec<String> = inner.split_whitespace().map(str::to_owned).collect();
    platforms.sort();
    platforms
}

/// Every distinct `out_name:` in the build workflow — the platform token that ends up in
/// `dig-node-<ver>-<out_name>` and `dign-<ver>-<out_name>`.
///
/// Read as a SET rather than a list because `out_name` also appears in the glibc-verification
/// matrix, which repeats tokens the build already emits. Repetition is therefore invisible here,
/// while a genuinely NEW platform — the case this guard exists for — is not.
fn built_platforms() -> Vec<String> {
    let mut platforms: Vec<String> = BUILD_YML
        .lines()
        .filter_map(|line| line.trim().strip_prefix("out_name:"))
        .map(|value| value.trim().to_owned())
        .collect();
    platforms.sort();
    platforms.dedup();
    platforms
}

/// The expectation must name EVERY platform the build produces, and no others.
///
/// Stated as equality, not containment, in both directions on purpose: a superset would demand an
/// asset that will never exist and wedge every release, while a subset is the silent hole above.
#[test]
fn the_expected_platforms_are_exactly_the_platforms_the_build_produces() {
    let expected = expected_platforms();
    let built = built_platforms();

    assert_eq!(
        expected, built,
        "the release-asset expectation in .github/actions/check-release-assets \
         has drifted from the build matrix in .github/workflows/build-binaries.yml.\n  \
         expected by the guard: {expected:?}\n  \
         produced by the build: {built:?}\n\
         A platform the build produces but the guard does not expect is NOT verified, so a \
         release missing its `dig-node-*` / `dign-*` binaries would still be promoted to \
         `releases/latest` and 404 every fresh install for that platform (dig-node#335). \
         Add the platform to PLATFORMS in the same change that adds it to the build."
    );
}

/// Sanity floor on the parsers themselves.
///
/// Both helpers above are string scrapes, and a scrape that silently matches NOTHING returns an
/// empty set — which compares equal to another empty set and turns the assertion above into a
/// vacuous pass. This is the control that keeps that from happening quietly.
#[test]
fn the_platform_sets_are_non_trivial() {
    assert!(
        expected_platforms().len() >= 5,
        "parsed too few expected platforms — the `PLATFORMS=(…)` scrape has broken, which would \
         make the drift check vacuous"
    );
    assert!(
        built_platforms().len() >= 5,
        "parsed too few built platforms — the `out_name:` scrape has broken, which would make \
         the drift check vacuous"
    );
}

/// Neither publisher may promote (dig-node#335).
///
/// A stable release is assembled by TWO workflows that do not wait for each other:
/// `release.yml` attaches the binaries, `package.yml` the native install packages. Both use
/// `softprops/action-gh-release`, **whose `make_latest` defaults to true**, so an omitted setting
/// is not a neutral omission — it hands `latest` to whichever job happens to finish first. On
/// v0.145.0 that was the packages job, five minutes before the binaries existed.
#[test]
fn no_asset_upload_may_promote_the_release_to_latest() {
    for (name, yml) in [("release.yml", RELEASE_YML), ("package.yml", PACKAGE_YML)] {
        let uploads = yml.matches("softprops/action-gh-release").count();
        let declines = yml.matches(r#"make_latest: "false""#).count();
        assert_eq!(
            uploads, declines,
            "{name} has {uploads} action-gh-release step(s) but {declines} `make_latest: \"false\"` \
             setting(s). The action DEFAULTS to make_latest: true, so every upload step must \
             decline promotion explicitly — otherwise attaching assets promotes a release that \
             may still be half-built (dig-node#335)."
        );
        assert!(
            !yml.contains(r#"make_latest: "true""#),
            "{name} must not promote from an upload step; promotion is release.yml's `promote` \
             job, which runs only after the asset guard passes"
        );
    }
}

/// Exactly ONE place moves `latest`, and it is the verified one.
///
/// `--latest=false` is a DEMOTION (the nightly channel keeps its pre-releases off `latest`) and
/// is counted separately — treating it as a promotion would make this guard reject the correct
/// code, and treating a promotion as a demotion would let #335 back in. The distinction is the
/// whole assertion, so it is drawn explicitly rather than by a substring search for `--latest`.
#[test]
fn exactly_one_site_promotes_a_release_to_latest() {
    let promotions: Vec<(&str, &str)> = [
        ("release.yml", RELEASE_YML),
        ("package.yml", PACKAGE_YML),
        ("nightly-release.yml", NIGHTLY_YML),
    ]
    .into_iter()
    .flat_map(|(name, yml)| {
        yml.lines()
            .filter(|line| line.contains("--latest") && !line.contains("--latest=false"))
            .map(move |line| (name, line.trim()))
    })
    .collect();

    assert_eq!(
        promotions.len(),
        1,
        "exactly one workflow site may move `releases/latest`, and it must be the `promote` job \
         in release.yml that runs after verification. Found {}: {promotions:#?}",
        promotions.len()
    );
    assert_eq!(
        promotions[0].0, "release.yml",
        "the single promotion site must live in release.yml, downstream of the asset guard"
    );
}

/// The guard must read asset STATE, not merely asset names (dig-node#335, finding 1).
///
/// GitHub creates an asset row when its upload STARTS, in state `starting`. A name is therefore
/// visible before its bytes are, and `verify` is ordered (`needs: publish`) only against
/// release.yml's own upload — package.yml is a separate workflow with no ordering relationship to
/// it. Without the state filter the poll can see all fourteen names while a `.msi` or `.pkg` is
/// still uploading, and promote a release whose download is incomplete: #335's observable
/// outcome through a shorter window.
///
/// Asserted here rather than in the workflow's self-test because that self-test feeds the action
/// a literal asset list and never reaches the network read this filter lives on.
///
/// Asserted against the `gh release view` COMMAND LINE specifically, never against the file as a
/// whole. The first version of this test searched the whole YAML and passed happily with the
/// filter DELETED from the query — because the comment above the query explains the filter and
/// contains the same text. A source-scanning assertion that matches its own explanatory prose is
/// satisfied by the documentation of the thing it is meant to require.
#[test]
fn the_guard_counts_only_fully_uploaded_assets() {
    let query = CHECK_ACTION_YML
        .lines()
        .find(|line| line.contains("gh release view"))
        .expect("check-release-assets must read the release's asset list with `gh release view`");

    assert!(
        query.contains(r#"select(.state == "uploaded")"#),
        "the `gh release view` query must filter to `state == \"uploaded\"`, but reads:\n  {query}\n\
         An asset row exists from the moment its upload BEGINS, so counting names alone lets a \
         release be promoted while a package is still uploading (dig-node#335)."
    );
    assert!(
        !CHECK_ACTION_YML.contains("sleep 60"),
        "a sleep is not a substitute for the state filter — it narrows the race without closing \
         it, and cannot be shown to fail, which is worse than leaving it visible"
    );
}
