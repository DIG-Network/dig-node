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
        .env("DIG_NODE_PORT", "1")
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
        .env("DIG_NODE_PORT", "1")
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

/// `status --json`'s `addr` field reflects `DIG_NODE_HOST`/`DIG_NODE_PORT` — the
/// canonical env-var names (renamed from the pre-#168 `DIG_COMPANION_*` names).
/// Regression guard for #168: proves the binary actually reads the new names, not
/// just that the old names were deleted from source.
#[test]
fn status_json_addr_reflects_dig_node_host_and_port_env_vars() {
    let out = bin()
        .args(["status", "--json"])
        .env("DIG_NODE_HOST", "127.0.0.1")
        .env("DIG_NODE_PORT", "2")
        .output()
        .expect("run dig-node status --json");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON object: {e}\n---\n{stdout}"));
    assert_eq!(v["addr"], Value::String("127.0.0.1:2".into()));
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

/// #526: `--scope <auto|system|user>` must be present on EVERY service verb, with `auto` as the
/// documented default. Asserted against the BUILT binary's own help — the only place that proves
/// the flag is actually wired into the CLI (a lib-level scope test cannot see a verb that forgot to
/// accept it). Reads help rather than running the verbs, so nothing is registered on the host.
#[test]
fn every_service_verb_accepts_the_scope_flag_defaulting_to_auto() {
    for verb in ["install", "uninstall", "start", "stop"] {
        let out = bin()
            .args([verb, "--help"])
            .output()
            .unwrap_or_else(|e| panic!("run dig-node {verb} --help: {e}"));
        assert!(out.status.success(), "`{verb} --help` must succeed");
        let help = String::from_utf8_lossy(&out.stdout);
        assert!(
            help.contains("--scope"),
            "`{verb}` must accept --scope: {help}"
        );
        assert!(
            help.contains("[default: auto]"),
            "`{verb} --scope` must default to auto so a caller passing no flag is unchanged: {help}"
        );
        for value in ["auto", "system", "user"] {
            assert!(
                help.contains(value),
                "`{verb} --scope` must offer `{value}`: {help}"
            );
        }
    }
}

/// A scope the CLI does not define must be a USAGE error (exit 2), never silently coerced to a
/// default — a typo'd `--scope sytem` must not quietly install at user scope.
#[test]
fn an_unknown_scope_value_is_a_usage_error() {
    let out = bin()
        .args(["install", "--scope", "sytem"])
        .output()
        .expect("run dig-node install --scope sytem");
    assert_eq!(
        out.status.code(),
        Some(2),
        "an invalid --scope value must be a clap usage error, not an install"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sytem"),
        "the error names the bad value: {stderr}"
    );
}
