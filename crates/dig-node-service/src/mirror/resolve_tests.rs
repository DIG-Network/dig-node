//! Tests for [`super::resolve`], in their own file because the fixtures are long enough that
//! inlining them would bury the module they document.

use std::cell::RefCell;
use std::collections::HashMap;

use super::plan::HeldMirror;
use super::resolve::resolve_landed_spends;
use super::runner::{MirrorEffects, ObservedCapsule, PassError};
use crate::mirror::plan::{Bond, ReclaimReason};
use crate::spend_audit::{
    kinds, Asset, AuditedBond, Authority, SpendIntent, SpendJournal, SpendKind, SpendLog,
    SpendStatus, Submission, TargetCoinId,
};

/// A height that is not a small number, not zero, and not equal to anything else in a fixture.
///
/// Chosen so an implementation that hard-codes a height, reuses an epoch, or defaults to zero
/// cannot accidentally agree with the assertion. It is the real mainnet height of the mirror coin
/// dig-node#412 piece 4 was verified against, which also makes it recognisable in a failure.
const LANDED_HEIGHT: u32 = 9_224_641;

fn id(tag: &str) -> String {
    let mut s = tag.to_string();
    while s.len() < 64 {
        s.push('0');
    }
    s.truncate(64);
    s
}

/// A chain double that keeps the three answers of
/// [`MirrorEffects::coin_confirmation`] genuinely apart.
///
/// `confirmations` holds the coins it can see and at what height; `unaskable` holds the coins it
/// cannot be asked about at all. Anything in neither is honestly absent. A double that could only
/// say "yes" and "no" could not express the `Err` case, and the `Err` case is where a resolver is
/// most likely to do harm.
#[derive(Default)]
struct Chain {
    confirmations: HashMap<String, u32>,
    unaskable: Vec<String>,
    asked: RefCell<Vec<String>>,
}

impl MirrorEffects for Chain {
    fn observe_disk(&self) -> Result<Vec<ObservedCapsule>, PassError> {
        Ok(Vec::new())
    }
    fn observe_chain(&self) -> Result<Vec<HeldMirror>, PassError> {
        Ok(Vec::new())
    }
    fn coin_confirmation(&self, coin_id: &str) -> Result<Option<u32>, PassError> {
        self.asked.borrow_mut().push(coin_id.to_string());
        if self.unaskable.iter().any(|c| c == coin_id) {
            return Err(PassError::Chain("the chain could not be asked".to_string()));
        }
        Ok(self.confirmations.get(coin_id).copied())
    }
    fn dig_balance_base_units(&self) -> Result<u64, PassError> {
        Ok(0)
    }
    fn reclaim(&self, _: &HeldMirror, _: ReclaimReason) -> Result<(), PassError> {
        panic!("resolution spends nothing")
    }
    fn create(&self, _: &Bond, _: i64, _: u64) -> Result<(), PassError> {
        panic!("resolution spends nothing")
    }
}

fn intent(store: &str, root: &str, epoch: i64) -> SpendIntent {
    SpendIntent {
        kind: SpendKind::new(kinds::MIRROR_COIN),
        purpose: "advertise a held capsule".to_string(),
        authority: Authority {
            principal: "node".to_string(),
            grant: "mirror.collateralisation".to_string(),
        },
        asset: Asset::Dig,
        amount_mojos: 1_010,
        fee_mojos: 0,
        store_id: Some(id(store)),
        bond: Some(AuditedBond {
            root: id(root),
            epoch,
        }),
    }
}

/// Open a spend and settle it the way a real pass does: broadcast, then drop the handle at the end
/// of the pass. That is what leaves `unresolved`, and it is the state under test.
///
/// Built through the real producer rather than by writing a JSONL line, so a fixture cannot encode
/// a record shape the node never actually writes.
fn open_spend(
    journal: &SpendJournal,
    store: &str,
    root: &str,
    epoch: i64,
    target: Option<&str>,
) -> String {
    let recorded = journal.begin(intent(store, root, epoch));
    let audit_id = recorded.id().to_string();
    journal.submitted(
        &recorded,
        Submission {
            intended_coin_id: target.map(|t| TargetCoinId(id(t))),
            funding_coin_ids: Vec::new(),
        },
    );
    drop(recorded);
    audit_id
}

fn status_of(log: &SpendLog, audit_id: &str) -> SpendStatus {
    log.ledger()
        .expect("ledger")
        .records
        .into_iter()
        .find(|r| r.id == audit_id)
        .expect("the record must exist")
        .status
}

fn mirror(coin: &str, store: &str, root: &str, epoch: i64) -> HeldMirror {
    HeldMirror {
        coin_id: id(coin),
        store_id: id(store),
        root: id(root),
        epoch,
        collateral_dig_base_units: 1_010,
    }
}

fn journal(dir: &std::path::Path) -> (SpendJournal, SpendLog) {
    let log = SpendLog::at(dir.join("spend-audit.jsonl"));
    (SpendJournal::new(log.clone()), log)
}

/// **Proves:** a reclaim whose coin the chain now shows becomes `Confirmed`, at the height the
/// CHAIN reported and against the coin id the record already carried.
///
/// **Catches:** the defect this whole module exists for — nothing calling `confirmed`, leaving every
/// broadcast mirror spend `unresolved` forever. It also catches a resolver that confirms on the
/// broadcast alone, because the fixture carries a SECOND spend, broadcast identically, whose coin
/// the chain does not have: an implementation that resolves what it submitted rather than what
/// landed confirms both and fails on the second assertion.
///
/// The height is asserted by value. A resolver that wrote `0`, or the epoch, or the record's own
/// revision, would satisfy "it is confirmed" and fail here.
#[test]
fn a_landed_reclaim_is_confirmed_at_the_height_the_chain_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (journal, log) = journal(dir.path());

    let landed = open_spend(&journal, "aa", "11", 7, Some("c1"));
    let still_flying = open_spend(&journal, "bb", "22", 7, Some("c2"));

    let chain = Chain {
        confirmations: HashMap::from([(id("c1"), LANDED_HEIGHT)]),
        ..Chain::default()
    };

    let summary = resolve_landed_spends(&journal, &chain, &[]);

    assert_eq!(summary.recorded, 1, "exactly the one landed spend resolves");
    assert_eq!(
        status_of(&log, &landed),
        SpendStatus::Confirmed {
            height: LANDED_HEIGHT,
            coin_id: TargetCoinId(id("c1")),
        },
        "the height and the coin come from the chain read, not from the attempt"
    );
    assert!(
        matches!(
            status_of(&log, &still_flying),
            SpendStatus::Unresolved { .. }
        ),
        "a spend the chain has no coin for stays unresolved; broadcasting is not landing"
    );
}

/// **Proves:** a chain that cannot ANSWER resolves nothing, and is kept distinct from a chain that
/// answers "absent".
///
/// **Catches:** folding `Err` into `Ok(None)` or, far worse, into a confirmation. A source that is
/// down for an hour would otherwise settle every open record on this node at once, on no evidence.
///
/// The fixture varies ONE actor and keeps an honest control: two identical spends, one whose coin
/// the chain confirms and one whose coin it cannot be asked about. Without the control this test
/// would also pass against a resolver that never resolves anything at all — which is the nearest
/// wrong implementation, and the one a naive "make Err safe" fix produces.
#[test]
fn a_chain_that_cannot_answer_resolves_nothing_while_its_neighbour_still_resolves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (journal, log) = journal(dir.path());

    let unaskable = open_spend(&journal, "aa", "11", 7, Some("c1"));
    let answerable = open_spend(&journal, "bb", "22", 7, Some("c2"));

    let chain = Chain {
        confirmations: HashMap::from([(id("c2"), LANDED_HEIGHT)]),
        unaskable: vec![id("c1")],
        ..Chain::default()
    };

    let summary = resolve_landed_spends(&journal, &chain, &[]);

    assert_eq!(
        summary.chain_unreadable, 1,
        "an unanswerable read is counted as an outage, never as an absence"
    );
    assert!(
        matches!(status_of(&log, &unaskable), SpendStatus::Unresolved { .. }),
        "a read that failed is not evidence about the coin, in either direction"
    );
    assert_eq!(
        summary.recorded, 1,
        "the control must still resolve, or this test passes against a resolver that does nothing"
    );
    assert!(
        matches!(status_of(&log, &answerable), SpendStatus::Confirmed { .. }),
        "one unreadable coin must not suppress resolution of an unrelated one"
    );
}

/// **Proves:** a CREATE is confirmed only against a coin the chain observation actually produced,
/// matched on all three of `(store, root, epoch)`.
///
/// **Catches:** the invented coin id. A create records `intended_coin_id: None` by design, so any
/// resolver that needs an id is tempted to derive one; the fixture's chain observation holds a coin
/// for the SAME store at a DIFFERENT root, so a matcher keyed on the store alone — the obvious
/// narrowing — confirms the wrong coin and fails here. The epoch axis is varied for the same
/// reason: a coin from last epoch is a real coin of this node's, and confirming this epoch's create
/// against it would report a bond that was never made.
#[test]
fn a_create_is_confirmed_only_against_a_coin_that_matches_store_root_and_epoch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (journal, log) = journal(dir.path());

    let create = open_spend(&journal, "aa", "11", 7, None);

    let wrong_root = mirror("c9", "aa", "99", 7);
    let wrong_epoch = mirror("c8", "aa", "11", 6);
    let chain = Chain {
        confirmations: HashMap::from([
            (id("c9"), LANDED_HEIGHT),
            (id("c8"), LANDED_HEIGHT),
            (id("c7"), LANDED_HEIGHT),
        ]),
        ..Chain::default()
    };

    let summary = resolve_landed_spends(&journal, &chain, &[wrong_root.clone(), wrong_epoch]);
    assert_eq!(
        summary.recorded, 0,
        "no coin matches all three terms, so nothing may be confirmed"
    );
    assert!(
        matches!(status_of(&log, &create), SpendStatus::Unresolved { .. }),
        "a create with no matching coin stays unresolved rather than borrowing a neighbour's"
    );
    assert!(
        !chain.asked.borrow().contains(&id("c9")),
        "a coin at the wrong root is not even a candidate, so it is never asked about"
    );

    // Now the real coin appears, alongside the two decoys that must still be ignored.
    let right = mirror("c7", "aa", "11", 7);
    let summary = resolve_landed_spends(&journal, &chain, &[wrong_root, right]);
    assert_eq!(summary.recorded, 1);
    assert_eq!(
        status_of(&log, &create),
        SpendStatus::Confirmed {
            height: LANDED_HEIGHT,
            coin_id: TargetCoinId(id("c7")),
        },
        "the confirmed coin id is the one the chain observation carried, never a derived one"
    );
}

/// **Proves:** when two open records claim one coin, NEITHER is confirmed.
///
/// **Catches:** resolving both, which asserts that two spends each created the same coin — false
/// about at least one of them, on the record whose whole purpose is to be true about money. It also
/// catches "resolve the first one", which is a coin flip dressed as an answer.
///
/// Reachable in production, not contrived: §25.4.6's in-flight suppression deliberately does not
/// suppress on `Unresolved` (a suppression that never lifts leaves a bond permanently
/// uncollateralised), so two open creates for one `(store, root, epoch)` are exactly what a pass
/// following the current rule produces after a broadcast whose fate is unknown.
#[test]
fn two_open_spends_claiming_one_coin_resolve_neither() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (journal, log) = journal(dir.path());

    let first = open_spend(&journal, "aa", "11", 7, None);
    let second = open_spend(&journal, "aa", "11", 7, None);

    let chain = Chain {
        confirmations: HashMap::from([(id("c7"), LANDED_HEIGHT)]),
        ..Chain::default()
    };

    let summary = resolve_landed_spends(&journal, &chain, &[mirror("c7", "aa", "11", 7)]);

    assert_eq!(summary.recorded, 0);
    assert_eq!(summary.ambiguous, 2, "both claimants are reported, not one");
    for audit_id in [&first, &second] {
        assert!(
            matches!(status_of(&log, audit_id), SpendStatus::Unresolved { .. }),
            "this node signed twice and cannot tell which signature landed; saying so is the \
             honest answer, and picking one is a fabrication"
        );
    }
}

/// **Proves:** a record that never reached the network is never confirmed, even when a coin
/// matching its bond is on chain.
///
/// **Catches:** a resolver keyed on the bond alone. A `Pending` record means nothing was handed to
/// a mempool, so a coin for that bond was created by some OTHER spend — a previous pass, or another
/// node at the same puzzle hash — and attributing it here would credit this attempt with a coin it
/// did not make and release the funding coins it still holds reserved.
///
/// # Two guards enforce this, and only ONE of them is load-bearing
///
/// [`super::resolve::resolve_landed_spends`] skips a `Pending` record when choosing what to look
/// up, and [`SpendJournal::resolve_landed`] refuses one when asked to write. The second masks the
/// first: relaxing the sweep's filter alone changes nothing observable, because the write still
/// refuses. So this test asserts the WRITER directly as well as through the sweep — an assertion
/// only through the sweep would pin a coincidence and stay green when the real guard was removed.
///
/// The sweep's filter is kept anyway, and deliberately: it is what stops a `Pending` record costing
/// a chain read per pass to reach a refusal that was decidable for free.
#[test]
fn a_spend_that_never_reached_the_network_is_not_confirmed_by_a_coin_that_matches_its_bond() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (journal, log) = journal(dir.path());

    // Begin and hold the handle: the record is `Pending`, and nothing was submitted.
    let recorded = journal.begin(intent("aa", "11", 7));
    let audit_id = recorded.id().to_string();

    let chain = Chain {
        confirmations: HashMap::from([(id("c7"), LANDED_HEIGHT)]),
        ..Chain::default()
    };
    let summary = resolve_landed_spends(&journal, &chain, &[mirror("c7", "aa", "11", 7)]);

    assert_eq!(summary.recorded, 0);
    assert_eq!(
        status_of(&log, &audit_id),
        SpendStatus::Pending,
        "a spend that never left this node cannot have created a coin"
    );

    // The authoritative guard, asked directly. The sweep above cannot exercise it, because the
    // sweep's own filter reaches the same answer first.
    assert_eq!(
        journal
            .resolve_landed(&audit_id, TargetCoinId(id("c7")), LANDED_HEIGHT)
            .expect("the record is readable"),
        crate::spend_audit::Resolution::NotOpen,
        "the writer must refuse a record that never reached the network, whatever asks it"
    );
    assert_eq!(
        status_of(&log, &audit_id),
        SpendStatus::Pending,
        "and refusing must write nothing at all"
    );
    drop(recorded);
}

/// **Proves:** an audit record with an unparseable entry resolves NOTHING, and does not even ask the
/// chain.
///
/// **Catches:** the sweep reading the folded ledger less carefully than its own sibling does.
/// [`crate::mirror::funding::committed_funding_coin_ids`] refuses an entire selection on a non-zero
/// [`crate::spend_audit::SpendLedger::unreadable_lines`], for the reason it states in its own
/// comment: the lost lines may be exactly the ones naming a committed coin. The same folded ledger
/// decides three things here, and a lost line corrupts all three — the `Confirmed` set that stops a
/// coin being attributed twice, the claimant count whose `> 1` guard then fails OPEN for the
/// survivor of a dropped rival, and the per-id revision fold, which can present a `Confirmed`
/// record as `Submitted` when it is the LATEST line that was lost.
///
/// # The fixture varies ONE thing
///
/// The record is a reclaim whose coin the chain genuinely confirms — the exact input
/// [`a_landed_reclaim_is_confirmed_at_the_height_the_chain_reported`] resolves successfully. The
/// only difference is one corrupt line appended after it. So a green here cannot come from there
/// being nothing to resolve: without the guard the sweep confirms this record, and the assertion on
/// `asked` shows the refusal happens at the ledger rather than incidentally at the chain read.
#[test]
fn an_unparseable_audit_entry_resolves_nothing_and_asks_the_chain_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (journal, log) = journal(dir.path());

    let audit_id = open_spend(&journal, "aa", "11", 7, Some("c9"));

    // A crash mid-append: the ordinary case this module already models. Written by hand because a
    // truncated line is by definition not something the producer can emit.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .expect("the audit log exists");
        f.write_all(b"{\"id\":\"trunc\",\"revi\n")
            .expect("append a torn line");
    }

    let chain = Chain {
        confirmations: HashMap::from([(id("c9"), LANDED_HEIGHT)]),
        ..Chain::default()
    };

    let summary = resolve_landed_spends(&journal, &chain, &[]);

    assert_eq!(
        summary.unreadable_lines, 1,
        "the refusal is reported, not only logged"
    );
    assert_eq!(
        summary.recorded, 0,
        "a lost line is a refusal, not a shorter ledger"
    );
    assert!(
        matches!(status_of(&log, &audit_id), SpendStatus::Unresolved { .. }),
        "a record left open by an unreadable ledger is the honest state"
    );
    assert!(
        chain.asked.borrow().is_empty(),
        "the refusal must happen at the ledger, before any chain read — otherwise it is only \
         accidentally safe"
    );
}

/// **Proves:** a create whose broadcast call ERRORED after the network had already admitted the
/// bundle is still chased and resolved, while a spend that failed at SIGNING never is.
///
/// **Catches:** the open set hard-coded as `Submitted | Unresolved` instead of asked of
/// [`SpendStatus::is_terminal`]. `mirror/lifecycle.rs`'s `Err` arm — the sibling of the very `Ok`
/// arm this resolver follows up — writes `Failed { stage: Broadcast }`, and
/// [`crate::spend_audit::FailureStage::money_may_have_moved`] already says that stage is an unknown
/// wearing a failure's name. Hard-coding the pair therefore left exactly the input class the module
/// documents as most needing to be chased permanently unchased: the coin sits on chain while
/// `dign spends` reports a failure for money that moved, which is dig-node#412's symptom surviving
/// the fix for it.
///
/// # Two records, opposite directions
///
/// Widening on `is_terminal` must not widen to everything. `Failed { Signing }` is terminal because
/// no signed bundle ever existed, and its bond is deliberately given a coin on chain too — a
/// resolver that widened by dropping the filter rather than by asking the stage confirms it and
/// fails here. The writer is asserted directly as well, because the sweep's filter and
/// [`SpendJournal::resolve_landed`]'s guard mask each other.
#[test]
fn a_create_whose_broadcast_errored_after_admission_is_resolved_but_a_signing_failure_is_not() {
    use crate::spend_audit::FailureStage;

    let dir = tempfile::tempdir().expect("tempdir");
    let (journal, log) = journal(dir.path());

    // The `Err` arm of `mirror/lifecycle.rs`'s broadcast: `failed`, never `submitted`. So there is
    // no `intended_coin_id`, and the create path's `(store, root, epoch)` key is the only key —
    // which is why this must be a create rather than a reclaim.
    let broadcast = journal.begin(intent("aa", "11", 7));
    let broadcast_id = broadcast.id().to_string();
    journal.failed(&broadcast, FailureStage::Broadcast, "connection reset");
    drop(broadcast);

    let signing = journal.begin(intent("bb", "22", 7));
    let signing_id = signing.id().to_string();
    journal.failed(&signing, FailureStage::Signing, "no spendable $DIG");
    drop(signing);

    let chain = Chain {
        confirmations: HashMap::from([(id("c1"), LANDED_HEIGHT), (id("c2"), LANDED_HEIGHT)]),
        ..Chain::default()
    };

    let summary = resolve_landed_spends(
        &journal,
        &chain,
        &[mirror("c1", "aa", "11", 7), mirror("c2", "bb", "22", 7)],
    );

    assert_eq!(
        summary.recorded, 1,
        "exactly the broadcast failure is chased"
    );
    assert_eq!(
        status_of(&log, &broadcast_id),
        SpendStatus::Confirmed {
            height: LANDED_HEIGHT,
            coin_id: TargetCoinId(id("c1")),
        },
        "a bundle the network admitted before the call errored did move money, and the record must \
         say so"
    );
    assert!(
        matches!(
            status_of(&log, &signing_id),
            SpendStatus::Failed {
                stage: FailureStage::Signing,
                ..
            }
        ),
        "nothing was ever signed, so a coin matching this bond was created by some OTHER spend"
    );

    // The authoritative guard, asked directly: the sweep's filter and the writer's mask each other.
    assert_eq!(
        journal
            .resolve_landed(&signing_id, TargetCoinId(id("c2")), LANDED_HEIGHT)
            .expect("the record is readable"),
        crate::spend_audit::Resolution::NotOpen,
        "the writer must refuse a spend that never reached the network, whatever asks it"
    );
}
