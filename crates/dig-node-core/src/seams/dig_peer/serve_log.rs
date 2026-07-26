//! Serve-side observability for the peer-facing read surface (#1595 / dig-node#104).
//!
//! During the #836 read-leg bring-up a holder served ~20 KB over `dig.fetchRange` while its log
//! showed NOTHING, so the only way to prove the serve had happened was `tcpdump` on the instance.
//! That left the most important question in a read diagnosis — *did the holder receive the request,
//! and what did it answer?* — ambiguous for many rounds: silence looked identical to "never asked".
//!
//! This module is the single vocabulary every peer-facing serve announces itself with, so the answer
//! is one `grep` away. It mirrors the client-side pattern that turned six blind iterations into
//! one-run diagnoses (dig-download's named-failing-step + per-candidate logs): name the peer, name the
//! content, name the OUTCOME.
//!
//! ## Levels
//!
//! * **INFO** — one line per request/answer pair: the outcome. This is the line an operator (or an
//!   e2e run) needs, so it must be visible at the default filter.
//! * **DEBUG** — the per-frame detail behind that outcome (offsets, chunk indices).
//!
//! ## What may never be logged
//!
//! Ids, counts, and outcomes only. **No served bytes, no proofs, no keys beyond the public content
//! ids** — a log that echoed the payload would make every operator log file a copy of the served
//! content, and one that echoed proofs would bloat it for no diagnostic gain. Pinned by the
//! `serve_logs_carry_ids_counts_and_outcomes_but_never_payload_or_proof` test.

use serde_json::Value;

/// The public ids naming what an inbound peer-facing serve was asked for, and by whom.
///
/// Every field is already public on the wire (the caller supplied the content ids and its own
/// mTLS-verified `peer_id`), so recording them leaks nothing the peer did not itself send.
pub(crate) struct ServeTarget<'a> {
    /// The mTLS-verified caller `peer_id` (64-hex), or empty on a caller-less/test session.
    pub peer: &'a str,
    /// The requested store id (64-hex).
    pub store: &'a str,
    /// The requested generation root (64-hex).
    pub root: &'a str,
    /// The requested resource retrieval key (64-hex).
    pub retrieval_key: &'a str,
}

impl<'a> ServeTarget<'a> {
    /// Read the content ids straight off an inbound `dig.fetchRange` request body.
    pub(crate) fn from_range_request(peer: &'a str, req: &'a Value) -> Self {
        let field = |name: &str| req.get(name).and_then(Value::as_str).unwrap_or("");
        ServeTarget {
            peer,
            store: field("store_id"),
            root: field("root"),
            retrieval_key: field("retrieval_key"),
        }
    }
}

/// How an inbound `dig.fetchRange` ended — the closed set of outcomes an INFO line reports.
pub(crate) enum RangeOutcome {
    /// Bytes were streamed to the caller.
    Served {
        /// Total bytes written across every frame.
        bytes: u64,
        /// How many frames those bytes were split into (the serve granularity).
        frames: u64,
        /// Whether the frames carried the verification metadata + inclusion proof (#1577).
        proof_attached: bool,
    },
    /// No bytes were streamed; the caller got an error or redirect frame instead.
    Refused {
        /// The greppable outcome name (see the `Refused` constructors below).
        outcome: &'static str,
        /// The catalogued JSON-RPC error code the caller was given.
        code: i64,
        /// A short, non-sensitive explanation.
        reason: String,
    },
}

impl RangeOutcome {
    /// The node does not hold the requested resource and knows no holder to name.
    pub(crate) fn not_held(code: i64, reason: String) -> Self {
        RangeOutcome::Refused {
            outcome: "not-held",
            code,
            reason,
        }
    }

    /// The requested offset lies past the end of the resource (an unsatisfiable range).
    pub(crate) fn bad_range(code: i64, reason: String) -> Self {
        RangeOutcome::Refused {
            outcome: "bad-range",
            code,
            reason,
        }
    }

    /// The caller was pointed at other holders instead of being served here — either because this
    /// node lacks the content (#165) or because serving it would exceed its outgoing budget (#30).
    pub(crate) fn redirected(code: i64, reason: String) -> Self {
        RangeOutcome::Refused {
            outcome: "redirect",
            code,
            reason,
        }
    }
}

/// Record an inbound `dig.fetchRange` as it arrives (DEBUG): who asked, for what, and for which span.
pub(crate) fn range_requested(target: &ServeTarget<'_>, offset: usize, length: usize) {
    tracing::debug!(
        peer_id = %target.peer,
        store_id = %target.store,
        root = %target.root,
        retrieval_key = %target.retrieval_key,
        offset,
        length,
        "peer serve: dig.fetchRange received"
    );
}

/// Record one streamed frame (DEBUG) — the granularity behind the INFO outcome line.
pub(crate) fn range_frame_served(offset: usize, bytes: usize, first_chunk_index: Option<u64>) {
    tracing::debug!(
        offset,
        bytes,
        first_chunk_index = first_chunk_index.unwrap_or_default(),
        chunk_aligned = first_chunk_index.is_some(),
        "peer serve: dig.fetchRange frame"
    );
}

/// Record how an inbound `dig.fetchRange` ended (INFO) — the one line a read diagnosis needs.
pub(crate) fn range_outcome(target: &ServeTarget<'_>, offset: usize, outcome: &RangeOutcome) {
    match outcome {
        RangeOutcome::Served {
            bytes,
            frames,
            proof_attached,
        } => tracing::info!(
            peer_id = %target.peer,
            store_id = %target.store,
            root = %target.root,
            retrieval_key = %target.retrieval_key,
            offset,
            served_bytes = bytes,
            frames,
            proof_attached,
            outcome = %"served",
            "peer serve: dig.fetchRange served"
        ),
        RangeOutcome::Refused {
            outcome: name,
            code,
            reason,
        } => tracing::info!(
            peer_id = %target.peer,
            store_id = %target.store,
            root = %target.root,
            retrieval_key = %target.retrieval_key,
            offset,
            code,
            reason = %reason,
            outcome = %name,
            "peer serve: dig.fetchRange refused"
        ),
    }
}

/// Why a `dig.getAvailability` item was answered the way it was — the distinction a diagnosis needs
/// between "we do not have it" and "we would not even look it up".
pub(crate) enum AvailabilityReason {
    /// The capsule is on disk and servable right now.
    Held,
    /// The capsule is not held (or the resource is not servable from it).
    NotHeld,
    /// The queried `root` is not a canonical 64-hex capsule key, so it can never name a held capsule
    /// and is refused without touching the filesystem.
    RejectedNonCanonicalKey,
    /// A store-granularity query (no `root`), answered by enumerating the held roots.
    StoreRoots {
        /// How many roots of that store are held.
        held: usize,
    },
}

impl AvailabilityReason {
    /// The stable, greppable name used in the log.
    fn name(&self) -> &'static str {
        match self {
            AvailabilityReason::Held => "held",
            AvailabilityReason::NotHeld => "not-held",
            AvailabilityReason::RejectedNonCanonicalKey => "rejected-non-canonical-key",
            AvailabilityReason::StoreRoots { .. } => "store-roots",
        }
    }
}

/// Record one `dig.getAvailability` answer (INFO): the queried content id, the answer, and the reason.
pub(crate) fn availability_answered(
    store: &str,
    root: Option<&str>,
    retrieval_key: Option<&str>,
    available: bool,
    reason: &AvailabilityReason,
) {
    let held_roots = match reason {
        AvailabilityReason::StoreRoots { held } => *held,
        _ => 0,
    };
    tracing::info!(
        store_id = %store,
        root = %root.unwrap_or(""),
        retrieval_key = %retrieval_key.unwrap_or(""),
        available,
        held_roots,
        reason = %reason.name(),
        "peer serve: dig.getAvailability answered"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serve_target_reads_the_content_ids_off_the_request() {
        let req = json!({"store_id": "aa", "root": "bb", "retrieval_key": "cc", "offset": 4});
        let target = ServeTarget::from_range_request("peer1", &req);
        assert_eq!(
            (target.peer, target.store, target.root, target.retrieval_key),
            ("peer1", "aa", "bb", "cc")
        );
    }

    #[test]
    fn serve_target_tolerates_a_request_missing_its_ids() {
        // A malformed request still produces a loggable target: the outcome line must never be the
        // thing that fails, or a diagnosis loses the very case it most needs to see.
        let empty = json!({});
        let target = ServeTarget::from_range_request("", &empty);
        assert_eq!(
            (target.store, target.root, target.retrieval_key),
            ("", "", "")
        );
    }

    #[test]
    fn refusal_outcomes_have_stable_greppable_names() {
        for (outcome, expected) in [
            (RangeOutcome::not_held(-32004, "miss".into()), "not-held"),
            (
                RangeOutcome::bad_range(-32007, "past end".into()),
                "bad-range",
            ),
            (
                RangeOutcome::redirected(-32008, "holders".into()),
                "redirect",
            ),
        ] {
            match outcome {
                RangeOutcome::Refused { outcome: name, .. } => assert_eq!(name, expected),
                RangeOutcome::Served { .. } => panic!("{expected} must be a refusal"),
            }
        }
    }

    #[test]
    fn availability_reasons_have_stable_greppable_names() {
        assert_eq!(AvailabilityReason::Held.name(), "held");
        assert_eq!(AvailabilityReason::NotHeld.name(), "not-held");
        assert_eq!(
            AvailabilityReason::RejectedNonCanonicalKey.name(),
            "rejected-non-canonical-key"
        );
        assert_eq!(
            AvailabilityReason::StoreRoots { held: 3 }.name(),
            "store-roots"
        );
    }
}
