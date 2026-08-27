//! `dign spends` — reading the automated-spend audit record (#376).
//!
//! # Why this reaches no node
//!
//! The record is a file on THIS machine, written by the daemon into the machine-wide state dir
//! (#501), and the `dign` the operator runs resolves that same dir. So the audit read needs no
//! running node — which is the point. A person asking "what did this thing spend?" is often asking
//! precisely because the node crashed, wedged, or was stopped, and an audit surface that goes dark
//! exactly when the node does is not an audit surface. [`crate::seed_export_cli`] is the existing
//! precedent for a local, node-free verb.
//!
//! The app reads the SAME file through the control plane; both views fold the same
//! [`crate::spend_audit::SpendLog`], so there is one record and one reader implementation rather
//! than two that must agree.
//!
//! # What the output must never do
//!
//! Present an intended coin as a confirmed one. Every row carries the status token and, where a coin
//! id is shown, whether the node OBSERVED it — `~` for expected, `#` for on chain. A person
//! scanning this list is deciding whether their money moved.

use serde_json::{json, Value};

use crate::cli::{ExitCode, Outcome};
use crate::spend_audit::{
    reconcile, ChainInventory, ReconcileReport, SpendLedger, SpendLog, SpendQuery, SpendRecord,
};

/// What `dign spends` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendsAction {
    /// List the record, filtered.
    List(SpendQuery),
    /// Show one entry in full, by its audit id.
    Show {
        /// The audit id (`sp_…`).
        id: String,
    },
    /// Compare the local record against the chain.
    Reconcile {
        /// The owner puzzle hash to ask the chain about.
        owner_puzzle_hash: String,
    },
}

/// Run a `dign spends` action against the node's own audit log.
pub fn run(action: SpendsAction) -> Result<Outcome, (ExitCode, String)> {
    run_against(&SpendLog::in_state_dir(), action, None)
}

/// The testable core: the same logic against an explicit log and an optional chain inventory.
///
/// `inventory` is `None` when no chain source is wired. `reconcile` then reports that it could not
/// check, rather than comparing against an empty chain — which would declare every confirmed entry
/// missing and manufacture an alarm out of a missing dependency.
pub fn run_against(
    log: &SpendLog,
    action: SpendsAction,
    inventory: Option<&dyn ChainInventory>,
) -> Result<Outcome, (ExitCode, String)> {
    match action {
        SpendsAction::List(query) => {
            let ledger = log.query(&query).map_err(|e| {
                (
                    ExitCode::IoError,
                    format!("cannot read the audit record: {e}"),
                )
            })?;
            Ok(list_outcome(log, &ledger))
        }
        SpendsAction::Show { id } => {
            let ledger = log.ledger().map_err(|e| {
                (
                    ExitCode::IoError,
                    format!("cannot read the audit record: {e}"),
                )
            })?;
            match ledger.records.iter().find(|r| r.id == id) {
                Some(rec) => Ok(show_outcome(rec)),
                None => Err((
                    ExitCode::Usage,
                    format!(
                        "no automated spend with id {id} in {}",
                        log.path().display()
                    ),
                )),
            }
        }
        SpendsAction::Reconcile { owner_puzzle_hash } => {
            let ledger = log.ledger().map_err(|e| {
                (
                    ExitCode::IoError,
                    format!("cannot read the audit record: {e}"),
                )
            })?;
            let Some(inventory) = inventory else {
                // Stated as a refusal, not as a clean result. "Nothing to report" and "I could not
                // look" are different answers, and printing the first for the second is the class of
                // lie this whole record exists to prevent.
                return Err((
                    ExitCode::NotServing,
                    "cannot reconcile: this node cannot read the chain's coin inventory yet, so \
                     there is nothing to compare the local record against. The record itself is \
                     unchanged and readable with `dign spends list`."
                        .to_string(),
                ));
            };
            let report = reconcile(&ledger, inventory, &owner_puzzle_hash)
                .map_err(|e| (ExitCode::IoError, format!("chain inventory failed: {e}")))?;
            Ok(reconcile_outcome(&report))
        }
    }
}

/// Render the list: one line per spend, newest first.
fn list_outcome(log: &SpendLog, ledger: &SpendLedger) -> Outcome {
    let mut summary = String::new();
    if ledger.records.is_empty() {
        summary.push_str("No automated spends match. This node has moved no money unattended.\n");
    }
    for rec in &ledger.records {
        summary.push_str(&format!("{}\n", human_line(rec)));
    }
    if ledger.unreadable_lines > 0 {
        // Surfaced, never swallowed: a trail that lost entries must not read as a shorter tidy one.
        summary.push_str(&format!(
            "\nWARNING: {} line(s) of {} could not be read. This record is INCOMPLETE.\n",
            ledger.unreadable_lines,
            log.path().display()
        ));
    }
    Outcome::new(
        summary.trim_end().to_string(),
        json!({
            "path": log.path().display().to_string(),
            "count": ledger.records.len(),
            "unreadable_lines": ledger.unreadable_lines,
            "spends": ledger.records.iter().map(record_json).collect::<Vec<_>>(),
        }),
    )
}

/// One human line for a spend.
fn human_line(rec: &SpendRecord) -> String {
    let chain = match rec.chain_reference() {
        Some(c) if c.confirmed => format!("  #{}", c.coin_id),
        Some(c) => format!("  ~{} (expected)", c.coin_id),
        None => String::new(),
    };
    let store = rec
        .store_id
        .as_deref()
        .map(|s| format!("  store={s}"))
        .unwrap_or_default();
    // WHY a spend did not happen is the most actionable field on the row — "insufficient funds" is
    // the difference between a node that is broken and a wallet that needs topping up — so it is
    // rendered inline rather than reserved for `show`.
    let why = match &rec.status {
        crate::spend_audit::SpendStatus::Failed { stage, reason } => {
            format!("\n    {stage} failed: {reason}")
        }
        crate::spend_audit::SpendStatus::Unresolved { reason } => {
            format!("\n    outcome unknown: {reason}")
        }
        _ => String::new(),
    };
    format!(
        "{}  {:<10}  {:<12}  {} {}  fee {}  by {}{}{}\n    {}  [{}]{why}",
        rec.id,
        rec.status.token(),
        rec.kind,
        rec.amount_mojos,
        rec.asset,
        rec.fee_mojos,
        rec.authority.principal,
        store,
        chain,
        rec.purpose,
        rec.authority.grant,
    )
}

/// The machine shape of one record. The `chain_reference` is folded in beside the raw fields so a
/// consumer never has to re-derive "is this coin id a fact or an intention".
fn record_json(rec: &SpendRecord) -> Value {
    let mut v = serde_json::to_value(rec).unwrap_or_else(|_| json!({}));
    if let Value::Object(map) = &mut v {
        map.insert(
            "status_token".to_string(),
            Value::String(rec.status.token().to_string()),
        );
        map.insert(
            "chain_reference".to_string(),
            serde_json::to_value(rec.chain_reference()).unwrap_or(Value::Null),
        );
    }
    v
}

/// Render one entry in full.
fn show_outcome(rec: &SpendRecord) -> Outcome {
    let summary = format!(
        "{}\n  status     {}\n  kind       {}\n  purpose    {}\n  amount     {} {}\n  fee        {} mojos\n  authority  {} via {}\n  store      {}\n  initiated  {} ms\n  updated    {} ms\n  funding    {}\n  chain      {}",
        rec.id,
        rec.status.token(),
        rec.kind,
        rec.purpose,
        rec.amount_mojos,
        rec.asset,
        rec.fee_mojos,
        rec.authority.principal,
        rec.authority.grant,
        rec.store_id.as_deref().unwrap_or("-"),
        rec.initiated_ms,
        rec.updated_ms,
        if rec.funding_coin_ids.is_empty() {
            "-".to_string()
        } else {
            rec.funding_coin_ids
                .iter()
                .map(|c| c.0.clone())
                .collect::<Vec<_>>()
                .join(", ")
        },
        match rec.chain_reference() {
            Some(c) if c.confirmed => format!("{} (confirmed on chain)", c.coin_id),
            Some(c) => format!("{} (EXPECTED, not observed)", c.coin_id),
            None => "-".to_string(),
        },
    );
    Outcome::new(summary, json!({ "spend": record_json(rec) }))
}

/// Render the reconciliation verdict.
fn reconcile_outcome(report: &ReconcileReport) -> Outcome {
    let summary = if report.is_clean() {
        format!(
            "The local record agrees with the chain ({} confirmed coin(s) present).",
            report.agreed.len()
        )
    } else {
        format!(
            "DISAGREEMENT between the local record and the chain:\n  \
             {} coin(s) on chain with NO audit entry: {}\n  \
             {} confirmed entry/entries whose coin the chain does not show: {}\n  \
             {} entry/entries the node never resolved: {}",
            report.unrecorded_on_chain.len(),
            join_or_dash(&report.unrecorded_on_chain),
            report.missing_on_chain.len(),
            join_or_dash(&report.missing_on_chain),
            report.unresolved.len(),
            join_or_dash(&report.unresolved),
        )
    };
    Outcome::new(
        summary,
        json!({
            "clean": report.is_clean(),
            "agreed": report.agreed,
            "missing_on_chain": report.missing_on_chain,
            "unrecorded_on_chain": report.unrecorded_on_chain,
            "unresolved": report.unresolved,
        }),
    )
}

fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend_audit::{
        kinds, Asset, Authority, FailureStage, SpendIntent, SpendJournal, SpendKind, SpendStatus,
        Submission, TargetCoinId,
    };

    const NOW: u64 = 1_767_225_600_000;

    fn clock() -> u64 {
        NOW
    }

    fn tmp_log() -> SpendLog {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("dig-node-spends-cli-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).expect("temp dir");
        SpendLog::at(dir.join("spend-audit.jsonl"))
    }

    fn intent(kind: &str, store: Option<&str>) -> SpendIntent {
        SpendIntent {
            kind: SpendKind::new(kind),
            purpose: "keep the store advertised".to_string(),
            authority: Authority {
                principal: "node".to_string(),
                grant: "settings.autoMirror".to_string(),
            },
            asset: Asset::Xch,
            amount_mojos: 1_000,
            fee_mojos: 10,
            store_id: store.map(str::to_string),
        }
    }

    /// A log holding one confirmed mirror-coin spend and one failed one.
    fn seeded_log() -> SpendLog {
        let log = tmp_log();
        let journal = SpendJournal::with_clock(log.clone(), clock);

        let ok = journal.begin(intent(kinds::MIRROR_COIN, Some("store-a")));
        journal.submitted(
            &ok,
            Submission {
                intended_coin_id: TargetCoinId("coin-ok".to_string()),
                funding_coin_ids: vec![],
            },
        );
        journal.confirmed(&ok, TargetCoinId("coin-ok".to_string()), 9_000_001);
        drop(ok);

        let bad = journal.begin(intent(kinds::MIRROR_COIN, Some("store-b")));
        journal.failed(&bad, FailureStage::Signing, "insufficient funds");
        drop(bad);

        log
    }

    /// **A blocked node does not read as an idle one.** The failed spend appears in the default
    /// listing beside the successful one — the fixture holds BOTH, because a log containing only a
    /// failure cannot tell "failures are listed" apart from "everything is listed".
    #[test]
    fn the_default_listing_shows_failures_beside_successes() {
        let log = seeded_log();
        let out = run_against(&log, SpendsAction::List(SpendQuery::default()), None).expect("list");
        assert_eq!(out.result["count"], 2);
        let tokens: Vec<&str> = out.result["spends"]
            .as_array()
            .expect("array")
            .iter()
            .map(|s| s["status_token"].as_str().expect("token"))
            .collect();
        assert!(tokens.contains(&"failed"), "got {tokens:?}");
        assert!(tokens.contains(&"confirmed"), "got {tokens:?}");
        assert!(out.summary.contains("insufficient funds"));
    }

    /// The status filter narrows to one row, and the row it keeps is the right one.
    #[test]
    fn the_status_filter_narrows_the_listing() {
        let log = seeded_log();
        let out = run_against(
            &log,
            SpendsAction::List(SpendQuery {
                status: Some("failed".to_string()),
                ..Default::default()
            }),
            None,
        )
        .expect("list");
        assert_eq!(out.result["count"], 1);
        assert_eq!(out.result["spends"][0]["status_token"], "failed");
    }

    /// The store filter narrows to the named store, and does NOT match the other one.
    #[test]
    fn the_store_filter_narrows_the_listing() {
        let log = seeded_log();
        let out = run_against(
            &log,
            SpendsAction::List(SpendQuery {
                store_id: Some("store-b".to_string()),
                ..Default::default()
            }),
            None,
        )
        .expect("list");
        assert_eq!(out.result["count"], 1);
        assert_eq!(out.result["spends"][0]["store_id"], "store-b");
    }

    /// **An expected coin is never printed as an observed one.** Both rows carry a coin id; only the
    /// confirmed one is marked on chain. The fixture keeps both so a renderer that hard-codes either
    /// marker fails instead of matching by luck.
    #[test]
    fn an_expected_coin_is_marked_differently_from_a_confirmed_one() {
        let log = tmp_log();
        let journal = SpendJournal::with_clock(log.clone(), clock);

        let pending = journal.begin(intent(kinds::MIRROR_COIN, Some("s1")));
        journal.submitted(
            &pending,
            Submission {
                intended_coin_id: TargetCoinId("coin-expected".to_string()),
                funding_coin_ids: vec![],
            },
        );
        journal.unresolved(&pending, "timed out");
        drop(pending);

        let done = journal.begin(intent(kinds::MIRROR_COIN, Some("s2")));
        journal.confirmed(&done, TargetCoinId("coin-real".to_string()), 12);
        drop(done);

        let out = run_against(&log, SpendsAction::List(SpendQuery::default()), None).expect("list");
        assert!(
            out.summary.contains("~coin-expected (expected)"),
            "an unobserved coin must be marked as expected: {}",
            out.summary
        );
        assert!(
            out.summary.contains("#coin-real"),
            "a confirmed coin is marked as on chain: {}",
            out.summary
        );

        let refs: Vec<bool> = out.result["spends"]
            .as_array()
            .expect("array")
            .iter()
            .map(|s| s["chain_reference"]["confirmed"].as_bool().expect("flag"))
            .collect();
        assert!(refs.contains(&true) && refs.contains(&false), "{refs:?}");
    }

    /// A corrupt line is reported to the person, in BOTH surfaces.
    #[test]
    fn an_incomplete_record_is_reported_as_incomplete() {
        use std::io::Write as _;
        let log = seeded_log();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .expect("open");
        f.write_all(b"garbage\n").expect("write");

        let out = run_against(&log, SpendsAction::List(SpendQuery::default()), None).expect("list");
        assert_eq!(out.result["unreadable_lines"], 1);
        assert!(out.summary.contains("INCOMPLETE"), "{}", out.summary);
    }

    /// An empty record says so plainly rather than printing nothing at all.
    #[test]
    fn an_empty_record_says_no_money_moved_unattended() {
        let out =
            run_against(&tmp_log(), SpendsAction::List(SpendQuery::default()), None).expect("list");
        assert_eq!(out.result["count"], 0);
        assert!(
            out.summary.contains("no money unattended"),
            "{}",
            out.summary
        );
    }

    /// `show` renders one entry, and an unknown id is a usage error rather than an empty success.
    #[test]
    fn show_finds_an_entry_and_refuses_an_unknown_id() {
        let log = seeded_log();
        let ledger = log.ledger().expect("ledger");
        let id = ledger.records[0].id.clone();

        let out = run_against(&log, SpendsAction::Show { id: id.clone() }, None).expect("show");
        assert_eq!(out.result["spend"]["id"], id);

        let err = run_against(
            &log,
            SpendsAction::Show {
                id: "sp_nope".to_string(),
            },
            None,
        )
        .expect_err("unknown id");
        assert_eq!(err.0, ExitCode::Usage);
    }

    struct FakeChain(Vec<String>);
    impl ChainInventory for FakeChain {
        fn owned_coin_ids(&self, _owner: &str) -> Result<Vec<String>, String> {
            Ok(self.0.clone())
        }
    }

    /// **"I could not look" is never rendered as "nothing to report".** With no inventory wired,
    /// reconcile REFUSES. The nearest wrong implementation compares against an empty chain, which
    /// would report the seeded confirmed coin as missing — so the fixture deliberately holds a
    /// confirmed coin, making that wrong version produce a visibly different answer.
    #[test]
    fn reconcile_without_a_chain_source_refuses_rather_than_reporting_clean() {
        let log = seeded_log();
        let err = run_against(
            &log,
            SpendsAction::Reconcile {
                owner_puzzle_hash: "ph".to_string(),
            },
            None,
        )
        .expect_err("no inventory");
        assert_eq!(err.0, ExitCode::NotServing);
        assert!(err.1.contains("cannot read the chain"), "{}", err.1);
    }

    /// With a chain source, a coin the chain shows and the record does not is reported as the alarm.
    #[test]
    fn reconcile_reports_a_coin_the_record_does_not_account_for() {
        let log = seeded_log();
        let chain = FakeChain(vec!["coin-ok".to_string(), "coin-orphan".to_string()]);
        let out = run_against(
            &log,
            SpendsAction::Reconcile {
                owner_puzzle_hash: "ph".to_string(),
            },
            Some(&chain),
        )
        .expect("reconcile");
        assert_eq!(out.result["clean"], false);
        assert_eq!(out.result["unrecorded_on_chain"][0], "coin-orphan");
        assert_eq!(out.result["agreed"][0], "coin-ok");
        assert!(out.summary.contains("DISAGREEMENT"), "{}", out.summary);
    }

    /// The clean case reads as clean — the honest control for the test above.
    #[test]
    fn reconcile_reports_agreement_when_the_chain_matches() {
        let log = seeded_log();
        let chain = FakeChain(vec!["coin-ok".to_string()]);
        let out = run_against(
            &log,
            SpendsAction::Reconcile {
                owner_puzzle_hash: "ph".to_string(),
            },
            Some(&chain),
        )
        .expect("reconcile");
        assert_eq!(out.result["clean"], true);
        assert!(
            out.summary.contains("agrees with the chain"),
            "{}",
            out.summary
        );
    }

    /// The `--json` envelope keys are a contract the app and scripts read. Pinned.
    #[test]
    fn the_json_listing_keys_are_stable() {
        let log = seeded_log();
        let out = run_against(&log, SpendsAction::List(SpendQuery::default()), None).expect("list");
        for key in ["path", "count", "unreadable_lines", "spends"] {
            assert!(out.result.get(key).is_some(), "missing {key}");
        }
        let first = &out.result["spends"][0];
        for key in [
            "id",
            "status",
            "status_token",
            "chain_reference",
            "authority",
        ] {
            assert!(first.get(key).is_some(), "missing spend.{key}");
        }
    }

    /// A record's authority is surfaced in the human output too: "on whose authority" is the whole
    /// point of an unapproved-spend record, and a field only a JSON consumer can see does not answer
    /// the person reading the terminal.
    #[test]
    fn the_human_output_states_on_whose_authority_the_node_spent() {
        let log = seeded_log();
        let out = run_against(&log, SpendsAction::List(SpendQuery::default()), None).expect("list");
        assert!(out.summary.contains("by node"), "{}", out.summary);
        assert!(
            out.summary.contains("settings.autoMirror"),
            "{}",
            out.summary
        );
    }

    /// A status token that matches nothing yields an empty list, not an error — and does not
    /// silently fall back to showing everything.
    #[test]
    fn a_filter_matching_nothing_returns_nothing_rather_than_everything() {
        let log = seeded_log();
        let out = run_against(
            &log,
            SpendsAction::List(SpendQuery {
                status: Some("submitted".to_string()),
                ..Default::default()
            }),
            None,
        )
        .expect("list");
        assert_eq!(out.result["count"], 0);
    }

    /// `--limit` caps the rows, keeping the NEWEST — a cap that kept the oldest would hide exactly
    /// the spends a person opened the command to see.
    #[test]
    fn a_limit_keeps_the_newest_rows() {
        let log = tmp_log();
        let journal = SpendJournal::with_clock(log.clone(), clock);
        // Distinct initiated_ms so "newest" is well defined rather than a tiebreak.
        for (i, store) in ["old", "new"].iter().enumerate() {
            let j =
                SpendJournal::with_clock(log.clone(), if i == 0 { || NOW } else { || NOW + 1_000 });
            let s = j.begin(intent(kinds::MIRROR_COIN, Some(store)));
            j.failed(&s, FailureStage::Signing, "x");
            drop(s);
        }
        let _ = journal;

        let out = run_against(
            &log,
            SpendsAction::List(SpendQuery {
                limit: Some(1),
                ..Default::default()
            }),
            None,
        )
        .expect("list");
        assert_eq!(out.result["count"], 1);
        assert_eq!(
            out.result["spends"][0]["store_id"], "new",
            "the cap must keep the newest row"
        );
    }

    /// A confirmed entry's status carries its height, and `show` prints it as confirmed rather than
    /// as expected.
    #[test]
    fn show_marks_a_confirmed_coin_as_observed() {
        let log = seeded_log();
        let ledger = log.ledger().expect("ledger");
        let confirmed = ledger
            .records
            .iter()
            .find(|r| matches!(r.status, SpendStatus::Confirmed { .. }))
            .expect("a confirmed row");
        let out = run_against(
            &log,
            SpendsAction::Show {
                id: confirmed.id.clone(),
            },
            None,
        )
        .expect("show");
        assert!(
            out.summary.contains("confirmed on chain"),
            "{}",
            out.summary
        );
    }
}
