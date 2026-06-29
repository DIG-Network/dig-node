//! Build script: capture the git commit SHA at compile time so the running
//! binary can report exactly which source it was built from (the `commit` field
//! of `GET /version` and `/.well-known/dig-node.json`).
//!
//! Agents correlate a deployed node back to a source revision via this SHA, so it
//! is emitted as a compile-time env var (`DIG_COMPANION_GIT_SHA`). When the build
//! happens outside a git checkout (e.g. a packaged source tarball), the SHA is
//! recorded as `"unknown"` rather than failing the build.

use std::process::Command;

fn main() {
    let sha = git_short_sha().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=DIG_COMPANION_GIT_SHA={sha}");
    // Rerun if the checked-out commit moves, so the embedded SHA stays accurate.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
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
