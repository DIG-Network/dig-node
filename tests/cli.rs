//! CLI contract tests against the BUILT binary: `--json` machine output and the
//! differentiated exit-code table. Cargo provides the binary path via
//! `CARGO_BIN_EXE_dig-node`, so these exercise the real invocation surface an
//! agent drives — not just the lib functions.

use std::process::Command;

use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dig-node"))
}

/// `status --json` against a port nothing listens on: success envelope to stdout,
/// `serving:false`, and exit code 1 (NOT_SERVING) so scripts can gate on liveness.
#[test]
fn status_json_reports_not_serving_with_exit_one() {
    let out = bin()
        .args(["status", "--json"])
        // A port nothing is bound to in CI → not serving.
        .env("DIG_COMPANION_PORT", "1")
        .output()
        .expect("run dig-node status --json");

    // Exit code 1 == NOT_SERVING (distinct from the generic failure codes).
    assert_eq!(out.status.code(), Some(1), "status not-serving must exit 1");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON object: {e}\n---\n{stdout}"));
    assert_eq!(v["ok"], Value::Bool(true));
    assert_eq!(v["action"], Value::String("status".into()));
    assert_eq!(v["service"], Value::String("dig-node".into()));
    assert_eq!(v["serving"], Value::Bool(false));
}

/// Default (no `--json`) `status` prints human prose to stdout, still exits 1.
#[test]
fn status_human_prose_still_exits_one_when_not_serving() {
    let out = bin()
        .arg("status")
        .env("DIG_COMPANION_PORT", "1")
        .output()
        .expect("run dig-node status");

    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Human prose, NOT JSON.
    assert!(
        stdout.contains("dig-node"),
        "prose should mention dig-node: {stdout}"
    );
    assert!(serde_json::from_str::<Value>(stdout.trim()).is_err());
}

/// A usage error (unknown subcommand) exits non-zero (clap's usage code), proving
/// argument errors are distinguished from runtime failures.
#[test]
fn unknown_subcommand_is_a_usage_error() {
    let out = bin()
        .arg("definitely-not-a-command")
        .output()
        .expect("run dig-node with a bad arg");
    assert!(!out.status.success(), "bad arg must fail");
}

/// `--version` prints the package version (clap's built-in, kept working).
#[test]
fn version_flag_prints_version() {
    let out = bin().arg("--version").output().expect("run --version");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "got: {stdout}");
}
