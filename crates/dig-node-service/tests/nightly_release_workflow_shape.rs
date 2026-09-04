//! Shape guard for the professional nightlies release system (dig_ecosystem #590/#592).
//!
//! This repo's release orchestrator (`nightly-release.yml`) is copied from the ecosystem's
//! REFERENCE nightlies implementation (DIG-Network/dig-updater) and has a precise, load-bearing
//! shape. These tests pin that shape so a careless edit — or a copy that drifts — cannot silently
//! revert the repo to the old "tag-and-release-on-every-merge" model:
//!
//!   1. The tagger NO LONGER triggers on push-to-main (the whole point of #590 — releases
//!      are batched to a nightly cron + manual dispatch instead of firing per merge).
//!   2. It DOES trigger on a midnight-UTC `schedule` cron and on `workflow_dispatch`.
//!   3. The STABLE channel keeps its idempotency keystone: skip cutting `vX.Y.Z` when that
//!      tag already exists (an unchanged version = the tag exists = a no-op).
//!   4. The NIGHTLY channel publishes a `prerelease: true` GitHub release under BOTH a dated
//!      `nightly-YYYYMMDD` tag and a force-moved rolling `nightly` tag, is never marked
//!      `latest`, and prunes old dated nightlies down to a retention window.
//!   5. Both channels preserve the RELEASE_TOKEN posture: no token configured => a clean
//!      no-op with a warning, never a half-release.
//!
//! The guard reads the workflow as text (not a YAML parser) on purpose: the invariants are
//! about the literal trigger/step shape a maintainer reads, and a text guard has no external
//! dependency and fails with a message that points at the exact line to fix.

use std::path::PathBuf;

/// A workflow file under `.github/workflows/`, resolved relative to this crate. The
/// `dig-node-service` crate sits two levels below the repo root (`crates/dig-node-service`), so
/// the workflows live at `../../.github/workflows/`.
fn workflow(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".github")
        .join("workflows")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The nightly + manual-dispatch release ORCHESTRATOR — the converted on-merge tagger.
fn nightly_release() -> String {
    workflow("nightly-release.yml")
}

/// Extract a workflow's top-level `on:` trigger block: the lines from `on:` (exclusive) up to
/// the next top-level key (a non-indented `word:` such as `jobs:`/`concurrency:`/`permissions:`).
/// Everything nested under `on:` stays; sibling top-level keys are excluded.
fn triggers_block(workflow: &str) -> String {
    let mut in_on = false;
    let mut lines: Vec<&str> = Vec::new();
    for line in workflow.lines() {
        if line.trim_start() == "on:" && !line.starts_with(' ') {
            in_on = true;
            continue;
        }
        if in_on {
            // A new top-level key (column-0, non-comment, non-blank) ends the `on:` block.
            let is_top_level_key = !line.is_empty()
                && !line.starts_with(' ')
                && !line.starts_with('#')
                && line.contains(':');
            if is_top_level_key {
                break;
            }
            lines.push(line);
        }
    }
    lines.join("\n")
}

/// Extract ONE job's block from a workflow: the lines from `  <name>:` (inclusive) up to the next
/// sibling job key at the same two-space indent. Scoping an assertion to a single job is what makes
/// it load-bearing — a string found anywhere in a 360-line workflow proves nothing about where it
/// sits, and "the packages exist somewhere" is exactly the coincidence these guards must not pin.
fn job_block(workflow: &str, name: &str) -> String {
    let header = format!("  {name}:");
    let mut lines: Vec<&str> = Vec::new();
    for line in workflow.lines() {
        if lines.is_empty() {
            if line == header {
                lines.push(line);
            }
            continue;
        }
        let is_sibling_job = line.starts_with("  ")
            && !line.starts_with("   ")
            && !line.trim_start().starts_with('#')
            && line.trim_end().ends_with(':');
        if is_sibling_job {
            break;
        }
        lines.push(line);
    }
    assert!(
        !lines.is_empty(),
        "workflow declares no `{name}:` job — expected it at two-space indent under `jobs:`"
    );
    lines.join("\n")
}

/// Extract ONE job's `if:` condition — the `if:` line plus every line indented DEEPER than it (the
/// continuation of a `>-` block scalar), with comment lines dropped.
///
/// Scoping to the condition rather than to the whole job block is what makes a NEGATIVE assertion
/// trustworthy here: the job block also carries the prose above the condition and every step below
/// it, so `!block.contains("schedule")` would be decided by a comment rather than by the trigger the
/// job actually answers to.
fn job_condition(workflow: &str, name: &str) -> String {
    let block = job_block(workflow, name);
    let mut lines: Vec<&str> = Vec::new();
    let mut if_indent = 0usize;
    for line in block.lines() {
        let trimmed = line.trim_start();
        if lines.is_empty() {
            if trimmed.starts_with("if:") {
                if_indent = line.len() - trimmed.len();
                lines.push(line);
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        // A line at or left of the `if:` key is the next job key (`runs-on:`), not the condition.
        if line.len() - trimmed.len() <= if_indent {
            break;
        }
        if trimmed.starts_with('#') {
            continue;
        }
        lines.push(line);
    }
    assert!(
        !lines.is_empty(),
        "the `{name}` job declares no `if:` condition, so it is gated by nothing at all"
    );
    lines.join("\n")
}

#[test]
fn tagger_no_longer_triggers_on_push_to_main() {
    let on = triggers_block(&nightly_release());
    assert!(
        !on.contains("push:"),
        "nightly-release.yml still declares a `push:` trigger — #590 removed push-to-main so \
         releases are cut by the nightly cron + manual dispatch, NOT on every merge. `on:` block:\n{on}"
    );
}

#[test]
fn tagger_triggers_on_midnight_cron_and_manual_dispatch() {
    let on = triggers_block(&nightly_release());
    assert!(
        on.contains("schedule:"),
        "nightly-release.yml must trigger on a `schedule:` cron. `on:` block:\n{on}"
    );
    assert!(
        on.contains("0 0 * * *"),
        "the nightly cron must be `0 0 * * *` (midnight UTC — GitHub cron is UTC). `on:` block:\n{on}"
    );
    assert!(
        on.contains("workflow_dispatch:"),
        "nightly-release.yml must support `workflow_dispatch:` so a maintainer can cut a release \
         on demand (#590). `on:` block:\n{on}"
    );
}

#[test]
fn manual_dispatch_offers_channel_and_force_inputs() {
    let wf = nightly_release();
    let on = triggers_block(&wf);
    assert!(
        on.contains("channel:"),
        "workflow_dispatch must expose a `channel` input (stable | nightly | both). `on:` block:\n{on}"
    );
    assert!(
        on.contains("force:"),
        "workflow_dispatch must expose a `force` input (re-cut a stable release even if the \
         version is unchanged). `on:` block:\n{on}"
    );
}

#[test]
fn stable_job_keeps_the_skip_if_already_tagged_guard() {
    let wf = nightly_release();
    // The idempotency keystone: an unchanged version means `vX.Y.Z` already exists, so the run
    // must skip cutting it. Both the local + remote tag existence check and the skip signal must
    // survive the conversion, or the nightly cron would try to re-tag an already-released version.
    assert!(
        wf.contains("refs/tags/$TAG"),
        "the stable job must still check whether the version's `vX.Y.Z` tag already exists"
    );
    assert!(
        wf.contains("skip=true"),
        "the stable job must still short-circuit (skip=true) when the version's tag already exists"
    );
}

/// CLAUDE.md 3.6-A: *the cron MUST NEVER cut a stable `vX.Y.Z`; a stable release is cut ONLY by a
/// manual `workflow_dispatch(channel: stable|both)`.*
///
/// The condition used to carry `github.event_name == 'schedule'` as an ALTERNATIVE to the dispatch
/// inputs, so every midnight the cron satisfied this job and published a real, tagged, permanent
/// release for whatever version `main` happened to carry — no human, no dispatch, and no gate beyond
/// ordinary CI. That is a release-integrity defect rather than a cosmetic one: it is how a version
/// whose own security gate had already FAILED once reached users (dig_ecosystem#698, #552).
///
/// Both halves are load-bearing. Asserting only that the dispatch event appears would still pass on
/// a condition that ORs the schedule back in, and asserting only that `schedule` is absent would
/// pass on a job that requires no particular event at all.
#[test]
fn stable_job_is_reachable_only_from_a_manual_dispatch() {
    let cond = job_condition(&nightly_release(), "stable");
    assert!(
        cond.contains("github.event_name == 'workflow_dispatch'"),
        "the stable job must REQUIRE `github.event_name == 'workflow_dispatch'` — a stable \
         `vX.Y.Z` is cut only by a deliberate human dispatch. `stable` condition:\n{cond}"
    );
    assert!(
        !cond.contains("'schedule'"),
        "the stable job condition still names the `schedule` event, so the midnight cron can cut a \
         real stable release unattended (CLAUDE.md 3.6-A: the cron cuts ONLY nightlies). \
         `stable` condition:\n{cond}"
    );
}

#[test]
fn force_recut_refuses_to_move_a_published_release_onto_a_different_commit() {
    let wf = nightly_release();
    // Supply-chain guard (#590 review): `force=true` may re-cut the SAME commit (a failed-build
    // retry) or repair a tag with no published release, but must NEVER silently move an existing
    // PUBLISHED release's tag onto a DIFFERENT commit — that would overwrite shipped binaries
    // with unreviewed code under the same version number. The force branch must (a) resolve the
    // existing tag's commit, (b) compare it against the commit this run would build, (c) check
    // whether a published (non-draft) GitHub release already sits at that tag, and (d) refuse
    // with a non-zero exit when both are true.
    assert!(
        wf.contains("TAG_COMMIT") && wf.contains("HEAD_COMMIT"),
        "the force branch must resolve both the existing tag's commit and this run's target \
         commit so it can compare them before moving the tag"
    );
    assert!(
        wf.contains("gh release view \"$TAG\"") && wf.contains("isDraft"),
        "the force branch must check whether a PUBLISHED (non-draft) release already exists at \
         the tag via `gh release view ... --json isDraft`"
    );
    assert!(
        wf.contains("IS_PUBLISHED_RELEASE") && wf.contains("TAG_COMMIT\" != \"$HEAD_COMMIT\""),
        "the force branch must refuse specifically when the release is published AND the tag's \
         commit differs from the target commit — same-commit re-cuts and no-release repairs \
         must remain allowed"
    );
    assert!(
        wf.contains("::error::refusing to force-move"),
        "the refusal must surface as a `::error::` annotation naming the guard, not a silent skip"
    );
}

#[test]
fn nightly_job_publishes_a_dated_and_a_rolling_prerelease() {
    let wf = nightly_release();
    assert!(
        wf.contains("--prerelease"),
        "the nightly job must publish a GitHub PRE-release (`--prerelease`), never a stable release"
    );
    assert!(
        wf.contains("nightly-$DATE") || wf.contains("nightly-${DATE}"),
        "the nightly job must publish under a DATED tag `nightly-YYYYMMDD` (built from $DATE)"
    );
    assert!(
        wf.contains("refs/tags/nightly"),
        "the nightly job must force-move a ROLLING `nightly` tag to the newest build"
    );
}

#[test]
fn nightly_release_is_never_marked_latest() {
    let wf = nightly_release();
    assert!(
        wf.contains("--latest=false"),
        "nightly releases must pass `--latest=false` — only a stable release may move `latest`, \
         so a nightly can never masquerade as the stable download (#590)"
    );
    assert!(
        !wf.contains("--latest=true"),
        "the nightly job must never mark a release `latest`"
    );
}

#[test]
fn nightly_job_prunes_to_a_retention_window() {
    let wf = nightly_release();
    // Retention keeps the newest N dated nightlies (default 14) + the rolling `nightly`, pruning
    // older dated releases AND their tags. The count is centralised in a `KEEP_NIGHTLIES` knob.
    assert!(
        wf.contains("KEEP_NIGHTLIES"),
        "the nightly job must define a `KEEP_NIGHTLIES` retention count"
    );
    assert!(
        wf.contains("--cleanup-tag"),
        "pruning must delete BOTH the GitHub release and its git tag (`gh release delete \
         --cleanup-tag`), never orphan a dated `nightly-YYYYMMDD` tag"
    );
}

#[test]
fn both_channels_no_op_without_release_token() {
    let wf = nightly_release();
    assert!(
        wf.contains("RELEASE_TOKEN"),
        "the release orchestrator must gate on RELEASE_TOKEN"
    );
    assert!(
        wf.contains("::warning::"),
        "a missing RELEASE_TOKEN must degrade to a clear `::warning::` no-op, never a half-release"
    );
}

/// The reusable build workflow both release paths call MUST exist and be `workflow_call`, or the
/// nightly + stable channels would each hand-roll a divergent build (the DRY invariant of #592).
#[test]
fn reusable_build_workflow_is_workflow_call_and_shared() {
    let build = workflow("build-binaries.yml");
    assert!(
        build.contains("workflow_call:"),
        "build-binaries.yml must be a reusable `on: workflow_call` workflow"
    );
    let nightly = nightly_release();
    let release = workflow("release.yml");
    assert!(
        nightly.contains("./.github/workflows/build-binaries.yml"),
        "the nightly channel must build via the shared build-binaries.yml (never a hand-rolled matrix)"
    );
    assert!(
        release.contains("./.github/workflows/build-binaries.yml"),
        "release.yml (stable) must build via the shared build-binaries.yml (never a hand-rolled matrix)"
    );
}

// ─────────────────── the nightly channel's NATIVE PACKAGES (dig_ecosystem#618) ───────────────────
//
// The beacon does not install dig-node from a raw binary — it hands a NATIVE PACKAGE to
// `msiexec`/`installer`/`dpkg` (dig-updater's `InstallMethod`). dig-updater's feedsign therefore
// resolves each component's assets by their native-package file names, and a nightly release that
// ships only bare binaries makes the whole nightly CHANNEL non-installable: feedsign fails closed
// with `no matching release assets`, reddening the signed feed for every channel it builds.
//
// These guards pin the wiring that fixes it, in the two places it can silently rot: `package.yml`
// must stay CALLABLE (and keep its own triggers), and the nightly channel must actually call it and
// wait for it before publishing.

/// The native-package builder — the .deb/.pkg/.msi definitions shared by the stable tag path and
/// the nightly channel.
fn package_workflow() -> String {
    workflow("package.yml")
}

#[test]
fn package_workflow_is_reusable_and_keeps_its_own_triggers() {
    let pkg = package_workflow();
    let on = triggers_block(&pkg);
    assert!(
        on.contains("workflow_call:"),
        "package.yml must be callable (`on: workflow_call`) so the nightly channel builds the \
         native packages from the SAME definitions as the stable tag path, never a copy. \
         `on:` block:\n{on}"
    );
    assert!(
        on.contains("version:"),
        "the `workflow_call` interface must take a `version` input — the nightly version is \
         synthesized at build time and exists in no version file. `on:` block:\n{on}"
    );
    // Making package.yml callable must not cost it its own triggers: the PR trigger is what
    // catches a broken package definition on the PR, and the `v*` tag trigger is what attaches
    // packages to a STABLE release.
    assert!(
        on.contains("pull_request:"),
        "package.yml must keep its `pull_request:` trigger — a broken package definition has to \
         fail on the PR, not on release night. `on:` block:\n{on}"
    );
    assert!(
        on.contains("\"v*\""),
        "package.yml must keep its `push: tags: v*` trigger — that is how the STABLE release gets \
         its native packages. `on:` block:\n{on}"
    );
}

#[test]
fn nightly_channel_builds_the_native_packages_from_the_shared_definitions() {
    let wf = nightly_release();
    assert!(
        wf.contains("./.github/workflows/package.yml"),
        "the nightly channel must build its native packages via the shared package.yml (never a \
         hand-rolled copy of the .deb/.pkg/.msi definitions)"
    );
    assert!(
        wf.contains("needs.nightly-meta.outputs.version"),
        "the native-package build must be stamped with the SAME synthesized nightly version as \
         the binaries (`nightly-meta.outputs.version`), or feedsign resolves two different \
         versions from one release"
    );
}

#[test]
fn nightly_publish_waits_for_the_packages_before_collecting_assets() {
    let wf = nightly_release();
    let publish = job_block(&wf, "nightly-publish");
    assert!(
        publish.contains("nightly-packages"),
        "`nightly-publish` must `needs:` the packages job. It collects assets with a blanket \
         `download-artifact` over the whole run, so WITHOUT that edge it can publish before the \
         packages exist — the nightly release would come out binaries-only exactly as it does \
         today, with every guard still green. `nightly-publish` job:\n{publish}"
    );
}

#[test]
fn nightly_publish_uploads_the_three_assets_feedsign_resolves() {
    let wf = nightly_release();
    let publish = job_block(&wf, "nightly-publish");
    // feedsign's `asset_name_parts` matches on these EXACT tails: `{prefix}_{version}_amd64.deb`,
    // `{prefix}-{version}-macos.pkg`, `{prefix}-{version}-windows-x64.msi`. Naming them in the
    // flatten step makes the collection explicit rather than an incidental consequence of a
    // blanket `find -type f`, so dropping one is a visible edit.
    for glob in ["_amd64.deb", "-macos.pkg", ".msi"] {
        assert!(
            publish.contains(glob),
            "`nightly-publish` must explicitly collect `*{glob}` — that is one of the three asset \
             names dig-updater's feedsign resolves for a native-package component. \
             `nightly-publish` job:\n{publish}"
        );
    }
}

/// The nightly `.deb` is amd64-ONLY by deliberate scope: feedsign's platform set has exactly one
/// Linux entry (`linux/x64`), so an arm64 nightly `.deb` would be built every night and resolved by
/// nobody. This guard is what keeps that a decision rather than a regression.
#[test]
fn nightly_deb_is_amd64_only() {
    let wf = nightly_release();
    let packages = job_block(&wf, "nightly-packages");
    assert!(
        packages.contains("amd64") && !packages.contains("arm64"),
        "the nightly packages job must request the amd64 `.deb` only — feedsign resolves a single \
         `linux/x64` Linux artifact, so a nightly arm64 build is pure CI cost. \
         `nightly-packages` job:\n{packages}"
    );
}
