//! `dign` is a FIRST-CLASS alias binary for `dig-node` (issue #548): the two bins share
//! ONE codepath (`dig_node_service::run()`), expose the SAME command surface + exit
//! codes, and each reflects its OWN invoked name (arg0) in `--help`/`--version` — so
//! `dign <args>` behaves identically to `dig-node <args>`.
//!
//! These run against the REAL built binaries (Cargo hands each `[[bin]]` path to
//! integration tests via `CARGO_BIN_EXE_<name>`), so they also prove the second
//! `[[bin]]` target actually builds — mirroring digstore's `cli_digs_alias.rs`.

use std::process::Command;

use serde_json::Value;

fn dig_node() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dig-node"))
}

fn dign() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dign"))
}

/// Both binaries build/run, and each `--version` reports the SAME semver — with its
/// OWN program name (clap prints "<bin> <semver>"): `dign 0.x.y` vs `dig-node 0.x.y`.
#[test]
fn dign_and_dig_node_report_the_same_version() {
    let dn = dig_node()
        .arg("--version")
        .output()
        .expect("dig-node --version");
    let dg = dign().arg("--version").output().expect("dign --version");
    assert!(dn.status.success() && dg.status.success());

    let dn_out = String::from_utf8_lossy(&dn.stdout);
    let dg_out = String::from_utf8_lossy(&dg.stdout);

    // The trailing semver token must match; the leading program name differs.
    let dn_ver = dn_out.split_whitespace().last().unwrap();
    let dg_ver = dg_out.split_whitespace().last().unwrap();
    assert_eq!(dn_ver, dg_ver, "same version: `{dn_out}` vs `{dg_out}`");
    assert!(
        dn_out.starts_with("dig-node "),
        "dig-node leads with its name: {dn_out}"
    );
    assert!(
        dg_out.starts_with("dign "),
        "dign leads with its own name: {dg_out}"
    );
}

/// `dign --help` renders its OWN name in the usage line, not a hardcoded "dig-node".
#[test]
fn dign_help_usage_shows_dign() {
    let out = dign().arg("--help").output().expect("dign --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Usage: dign"),
        "usage line must read `dign`, got:\n{stdout}"
    );
    // Discriminating: "dig-node" must not leak into the alias's usage (note "dign" is
    // NOT a substring of "dig-node", so this catches a hardcoded program name).
    assert!(
        !stdout.contains("Usage: dig-node"),
        "the `dign` help must not report `dig-node`:\n{stdout}"
    );
}

/// `dign` runs the SAME dispatch path: `dign status --json` against a dead port fails
/// with the identical envelope `dig-node status --json` produces (exit 1 NOT_SERVING,
/// `serving:false`, and the stable `service:"dig-node"` identity — the alias does NOT
/// rename the SERVICE, only the invoked binary).
#[test]
fn dign_dispatches_commands_like_dig_node() {
    let dg = dign()
        .args(["status", "--json"])
        .env("DIG_NODE_PORT", "1")
        .output()
        .expect("dign status --json");
    assert_eq!(
        dg.status.code(),
        Some(1),
        "NOT_SERVING exits 1 under dign too"
    );

    let stdout = String::from_utf8_lossy(&dg.stdout);
    let v: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON object: {e}\n---\n{stdout}"));
    assert_eq!(v["ok"], Value::Bool(true));
    assert_eq!(v["action"], Value::String("status".into()));
    // The alias renames the BINARY, never the service identity string.
    assert_eq!(v["service"], Value::String("dig-node".into()));
    assert_eq!(v["serving"], Value::Bool(false));
}

/// The two bins expose the IDENTICAL command surface: an unknown subcommand is a usage
/// error (clap exit 2) under BOTH, proving they share one parser/dispatch path.
#[test]
fn dign_rejects_unknown_subcommand_like_dig_node() {
    let dg = dign().arg("definitely-not-a-command").output().unwrap();
    let dn = dig_node().arg("definitely-not-a-command").output().unwrap();
    assert_eq!(
        dg.status.code(),
        dn.status.code(),
        "both fail an unknown subcommand with the same code"
    );
    assert!(!dg.status.success(), "bad arg must fail under dign");
}
