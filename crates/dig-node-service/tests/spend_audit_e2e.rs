//! End-to-end: an automated spend is recorded by the node's own journal and read back out of the
//! SHIPPED `dign` binary (#376).
//!
//! The unit tests drive the journal and the renderer in-process. This file is the one that proves
//! the thing a person actually does: money moved without approval, and `dign spends` shows it. It
//! crosses every seam the in-process tests skip — the real state-dir resolution
//! (`DIG_NODE_STATE_DIR`), the real file on disk, a SEPARATE process, the clap surface, and the
//! `--json` envelope. Each of those has been an independent source of "the library works and the
//! command does not".
//!
//! The producer that will cause these spends for real is a later ticket; what is fixed here is that
//! the record written by the write path is the record the binary reads, at the same resolved path.

use std::path::PathBuf;
use std::process::Command;

use dig_node_service::spend_audit::{
    kinds, Asset, Authority, FailureStage, SpendIntent, SpendJournal, SpendKind, SpendLog,
    Submission, TargetCoinId, SPEND_AUDIT_FILE,
};

fn dign() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dign"))
}

/// A private state dir, standing in for the machine-wide one the daemon and the CLI share.
fn state_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("dig-node-spend-e2e-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("state dir");
    dir
}

fn intent(store: &str) -> SpendIntent {
    SpendIntent {
        kind: SpendKind::new(kinds::MIRROR_COIN),
        purpose: "keep this store advertised on chain".to_string(),
        authority: Authority {
            principal: "node".to_string(),
            grant: "settings.autoMirror".to_string(),
        },
        asset: Asset::Xch,
        amount_mojos: 1_000,
        fee_mojos: 10,
        store_id: Some(store.to_string()),
        bond: None,
    }
}

/// **The whole point, end to end.** Two automated spends happen — one confirms, one is refused for
/// want of funds — and the shipped binary shows BOTH, with the confirmed one carrying a coin id a
/// person can paste into an explorer.
///
/// The fixture holds one of each on purpose. A fixture with only the successful spend cannot tell
/// "failures are recorded" apart from "everything is recorded", and a fixture with only the failure
/// cannot tell a working confirmation path from a broken one.
#[test]
fn an_automated_spend_is_written_by_the_node_and_read_back_by_dign() {
    let dir = state_dir("roundtrip");
    let log = SpendLog::at(dir.join(SPEND_AUDIT_FILE));
    let journal = SpendJournal::new(log);

    let ok = journal.begin(intent("store-alpha"));
    journal.submitted(
        &ok,
        Submission {
            intended_coin_id: TargetCoinId("a".repeat(64)),
            funding_coin_ids: vec![],
        },
    );
    journal.confirmed(&ok, TargetCoinId("a".repeat(64)), 9_172_077);
    let confirmed_id = ok.id().to_string();
    drop(ok);

    let broke = journal.begin(intent("store-beta"));
    journal.failed(&broke, FailureStage::Signing, "insufficient funds");
    drop(broke);

    // The operator's command. A separate process, resolving the state dir on its own.
    let out = Command::new(dign())
        .args(["spends", "list", "--json"])
        .env("DIG_NODE_STATE_DIR", &dir)
        .output()
        .expect("run dign");
    assert!(
        out.status.success(),
        "dign spends list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("dign emitted one JSON object");
    assert_eq!(v["ok"], true);
    assert_eq!(v["action"], "spends");
    assert_eq!(v["count"], 2, "both spends are visible: {v}");

    let spends = v["spends"].as_array().expect("spends array");
    let confirmed = spends
        .iter()
        .find(|s| s["status_token"] == "confirmed")
        .expect("the confirmed spend");
    assert_eq!(confirmed["id"], confirmed_id);
    assert_eq!(confirmed["status"]["height"], 9_172_077);
    assert_eq!(confirmed["chain_reference"]["coin_id"], "a".repeat(64));
    assert_eq!(
        confirmed["chain_reference"]["confirmed"], true,
        "the coin was observed, so it is reported as observed"
    );

    let failed = spends
        .iter()
        .find(|s| s["status_token"] == "failed")
        .expect("the failed spend is an ENTRY, not an omission");
    assert_eq!(failed["store_id"], "store-beta");
    assert_eq!(failed["status"]["reason"], "insufficient funds");
    assert_eq!(failed["status"]["stage"], "signing");
    assert_eq!(
        failed["chain_reference"],
        serde_json::Value::Null,
        "a spend that never reached the network claims no coin"
    );
}

/// The human surface answers the question a person actually asked: what did this thing spend, on
/// whose say-so, and did it work.
#[test]
fn the_human_output_answers_what_and_on_whose_authority() {
    let dir = state_dir("human");
    let journal = SpendJournal::new(SpendLog::at(dir.join(SPEND_AUDIT_FILE)));
    let s = journal.begin(intent("store-gamma"));
    journal.failed(&s, FailureStage::Signing, "insufficient funds");
    drop(s);

    let out = Command::new(dign())
        .args(["spends", "list"])
        .env("DIG_NODE_STATE_DIR", &dir)
        .output()
        .expect("run dign");
    assert!(
        out.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // In the DEFAULT mode human prose is the output, on stdout. It moves to stderr only under
    // `--json`, where stdout is reserved for the single machine object.
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("store-gamma"), "{text}");
    assert!(text.contains("settings.autoMirror"), "{text}");
    assert!(text.contains("insufficient funds"), "{text}");
}

/// A node that has never spent unattended says so, and exits 0 — an audit read finding nothing is a
/// successful audit read, not an error.
#[test]
fn a_node_that_never_spent_unattended_reports_an_empty_record() {
    let dir = state_dir("empty");
    let out = Command::new(dign())
        .args(["spends", "list", "--json"])
        .env("DIG_NODE_STATE_DIR", &dir)
        .output()
        .expect("run dign");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["count"], 0);
    assert_eq!(v["unreadable_lines"], 0);
}

/// The filters work through the real command line, not merely through the query struct: a `--status`
/// the clap layer failed to forward would silently list everything, which is the failure mode most
/// likely to go unnoticed in an audit tool.
#[test]
fn a_status_filter_passed_on_the_command_line_actually_narrows() {
    let dir = state_dir("filter");
    let journal = SpendJournal::new(SpendLog::at(dir.join(SPEND_AUDIT_FILE)));

    let ok = journal.begin(intent("store-one"));
    journal.confirmed(&ok, TargetCoinId("b".repeat(64)), 10);
    drop(ok);
    let bad = journal.begin(intent("store-two"));
    journal.failed(&bad, FailureStage::Broadcast, "mempool rejected");
    drop(bad);

    let out = Command::new(dign())
        .args(["spends", "list", "--status", "failed", "--json"])
        .env("DIG_NODE_STATE_DIR", &dir)
        .output()
        .expect("run dign");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["count"], 1, "the filter must narrow: {v}");
    assert_eq!(v["spends"][0]["store_id"], "store-two");
}

/// `show` reaches one entry by the id `list` printed, through the real binary.
#[test]
fn show_reaches_one_entry_by_the_id_list_printed() {
    let dir = state_dir("show");
    let journal = SpendJournal::new(SpendLog::at(dir.join(SPEND_AUDIT_FILE)));
    let s = journal.begin(intent("store-delta"));
    journal.confirmed(&s, TargetCoinId("c".repeat(64)), 77);
    let id = s.id().to_string();
    drop(s);

    let out = Command::new(dign())
        .args(["spends", "show", &id, "--json"])
        .env("DIG_NODE_STATE_DIR", &dir)
        .output()
        .expect("run dign");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["spend"]["id"], id);
    assert_eq!(v["spend"]["status"]["height"], 77);
}

/// An unknown id is a USAGE failure with a non-zero exit code, so a script can branch on it rather
/// than mistaking an absent entry for an empty-but-successful answer.
#[test]
fn an_unknown_id_exits_non_zero() {
    let dir = state_dir("unknown");
    let out = Command::new(dign())
        .args(["spends", "show", "sp_does_not_exist", "--json"])
        .env("DIG_NODE_STATE_DIR", &dir)
        .output()
        .expect("run dign");
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json error envelope");
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "USAGE");
}

/// **Reconcile refuses rather than reporting clean** when the node cannot read the chain. A confirmed
/// entry is present, so an implementation that compared against an empty chain would print a
/// discrepancy, and one that skipped the check would print "clean" — both visibly different from the
/// refusal this asserts.
#[test]
fn reconcile_without_a_chain_source_refuses_rather_than_claiming_agreement() {
    let dir = state_dir("reconcile");
    let journal = SpendJournal::new(SpendLog::at(dir.join(SPEND_AUDIT_FILE)));
    let s = journal.begin(intent("store-eps"));
    journal.confirmed(&s, TargetCoinId("d".repeat(64)), 5);
    drop(s);

    let out = Command::new(dign())
        .args(["spends", "reconcile", &"e".repeat(64), "--json"])
        .env("DIG_NODE_STATE_DIR", &dir)
        .output()
        .expect("run dign");
    assert!(!out.status.success(), "an unperformed check is not a pass");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["ok"], false);
    assert_eq!(v.get("clean"), None, "it must not report a verdict at all");
}
