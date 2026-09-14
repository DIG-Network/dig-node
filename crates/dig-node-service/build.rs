//! Build script: capture the git commit SHA at compile time so the running
//! binary can report exactly which source it was built from (the `commit` field
//! of `GET /version` and `/.well-known/dig-node.json`).
//!
//! Agents correlate a deployed node back to a source revision via this SHA, so it
//! is emitted as a compile-time env var (`DIG_NODE_GIT_SHA`). When the build
//! happens outside a git checkout (e.g. a packaged source tarball), the SHA is
//! recorded as `"unknown"` rather than failing the build.
//!
//! On Windows this also embeds the branded DIG application icon
//! (`../../assets/dig.rc`, dig_ecosystem#2917) into the `dig-node` and `dign`
//! binaries only -- see `embed_icon` below for why `fake_beacon_cli` is excluded.

use std::process::Command;

fn main() {
    let sha = git_short_sha().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=DIG_NODE_GIT_SHA={sha}");
    // Rerun if the checked-out commit moves, so the embedded SHA stays accurate.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    #[cfg(windows)]
    embed_icon();
}

/// Compile the branded DIG icon into `dig-node` and `dign` only.
///
/// `embed_resource::compile` (unscoped) emits `cargo:rustc-link-arg-bins`, which
/// reaches EVERY bin this crate produces -- including `fake_beacon_cli`, a test
/// fixture that stands in for the real (separate-repo) `dig-updater` beacon CLI
/// and must never carry the DIG brand. `compile_for` scopes the link line to the
/// two shipped binary names instead, so `fake_beacon_cli` stays icon-less.
///
/// `.manifest_required()`/`.expect(..)` is deliberate: an environment that cannot
/// compile a resource must fail the build loudly rather than silently ship an
/// unbranded `dig-node`/`dign`.
#[cfg(windows)]
fn embed_icon() {
    embed_resource::compile_for(
        "../../assets/dig.rc",
        &["dig-node", "dign"],
        embed_resource::NONE,
    )
    .manifest_required()
    .expect("failed to compile assets/dig.rc — no usable Windows resource compiler?");

    println!("cargo:rerun-if-changed=../../assets/dig.rc");
    println!("cargo:rerun-if-changed=../../assets/dig.ico");
}

/// The short git SHA of HEAD, or `None` outside a git checkout / without git.
fn git_short_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if sha.is_empty() {
        None
    } else {
        Some(sha)
    }
}
