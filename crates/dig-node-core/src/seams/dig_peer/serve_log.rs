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
//!
//! ## Why every id is a [`SafeId`]
//!
//! Every id on this surface arrives from an UNTRUSTED peer, inside a frame capped only at 64 KiB. A
//! verbatim id would hand any peer two attacks on the log's evidentiary value: writing ~64 KiB of junk
//! per request (an amplification the operator pays for in disk and IO), and — because a JSON string may
//! contain `\n` — FORGING a whole extra record, e.g. a fake `outcome=served proof_attached=true` for a
//! request that served nothing. That destroys the exact property this module exists to provide.
//!
//! So no `&str` id ever reaches a `tracing` macro here. Ids are logged through [`SafeId`], which emits
//! the value only when it is a canonical 64-hex content id and a short fixed sentinel otherwise — a
//! form that is bounded and control-character-free by construction, not by remembering to escape.
//!
//! ## Why the wrappers live in the STRUCT, not at the log site
//!
//! Wrapping at the `tracing!` call would be a guard every future log line has to remember, and #1609
//! records what that is worth in practice: a sibling crate carefully sentinelled a peer id where it was
//! REPORTED, while the error type's own `Display` went on re-embedding the raw id — so the raw value
//! still reached the log, and a test passed because its mock happened to use a benign id.
//!
//! Hence [`ServeTarget`] holds [`SafeId`]s and [`RangeOutcome::Refused`] holds a [`SafeText`], rather
//! than either holding a `&str`/`String` that a call site wraps on the way out. The neutralizing happens
//! at construction, once, so there is no way to build one of these records around a raw peer string.

use serde_json::Value;
use std::fmt;

/// Emitted in place of an id that is not a canonical content id — bounded, and no control characters.
const NON_CANONICAL: &str = "<non-canonical>";

/// Emitted in place of an id the request did not carry at all (a store-granularity query, say).
const ABSENT: &str = "<absent>";

/// A peer-supplied identifier in a form that is SAFE to put in a log record.
///
/// `Display` renders the id verbatim only if it is a canonical 64-hex content id
/// ([`crate::is_canonical_hex_id`]) — the only shape that can name real content, and the shape a
/// diagnosis actually needs to read. Anything else renders as a fixed sentinel, so an id can neither
/// bloat a line nor inject one. A non-canonical id loses no diagnostic value: it could never have named
/// held content, and the accompanying outcome/reason already says why the request failed.
pub(crate) struct SafeId<'a>(&'a str);

impl<'a> SafeId<'a> {
    /// Wrap a peer-supplied id for logging. Total, by design: there is no fallible path that could
    /// tempt a call site into logging the raw value instead.
    pub(crate) fn new(id: &'a str) -> Self {
        SafeId(id)
    }
}

impl fmt::Display for SafeId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            "" => f.write_str(ABSENT),
            id if crate::is_canonical_hex_id(id) => f.write_str(id),
            _ => f.write_str(NON_CANONICAL),
        }
    }
}

/// The longest free-form explanation a log record will carry.
///
/// Free-form text cannot be whitelisted the way an id can, so it is BOUNDED instead. 200 characters
/// holds every catalogued serve message with room to spare, while capping what one request can write to
/// the log at a constant — the amplification half of the same attack a 64 KiB frame otherwise permits.
const MAX_REASON_CHARS: usize = 200;

/// Replaces each control character in free-form text — one glyph per character, so the bound above still
/// holds after substitution.
const CONTROL_REPLACEMENT: char = '\u{fffd}';

/// Free-form explanatory text in a form that is SAFE to put in a log record.
///
/// Unlike an id, an explanation has no canonical shape to check against, so this cannot reject — it
/// NEUTRALIZES: every control character becomes [`CONTROL_REPLACEMENT`] and the result is truncated to
/// [`MAX_REASON_CHARS`]. That removes both hazards a verbatim string carries — a `\n` that would end the
/// record and forge another, and unbounded length — while keeping the text readable.
///
/// It exists as a TYPE, and [`RangeOutcome::Refused`] stores it rather than a `String`, for the reason
/// #1609 records: sanitizing at the log site is not sanitizing, because the next `Refused` anyone
/// constructs starts again from a raw `String`. Holding the wrapper in the struct means the neutralizing
/// happens once, at the boundary, however the outcome is built.
pub(crate) struct SafeText(String);

impl SafeText {
    /// Neutralize free-form text for logging. Total: there is no failure mode a call site could handle
    /// by logging the raw value instead.
    pub(crate) fn new(text: impl AsRef<str>) -> Self {
        SafeText(
            text.as_ref()
                .chars()
                .map(|c| {
                    if c.is_control() {
                        CONTROL_REPLACEMENT
                    } else {
                        c
                    }
                })
                .take(MAX_REASON_CHARS)
                .collect(),
        )
    }
}

impl fmt::Display for SafeText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The public ids naming what an inbound peer-facing serve was asked for, and by whom.
///
/// Every field is already public on the wire (the caller supplied the content ids and its own
/// mTLS-verified `peer_id`), so recording them leaks nothing the peer did not itself send — but each is
/// held as a [`SafeId`] so that what reaches the log is bounded and unforgeable regardless.
pub(crate) struct ServeTarget<'a> {
    /// The mTLS-verified caller `peer_id` (64-hex), or absent on a caller-less/test session.
    pub peer: SafeId<'a>,
    /// The requested store id (64-hex).
    pub store: SafeId<'a>,
    /// The requested generation root (64-hex).
    pub root: SafeId<'a>,
    /// The requested resource retrieval key (64-hex).
    pub retrieval_key: SafeId<'a>,
}

impl<'a> ServeTarget<'a> {
    /// Read the content ids straight off an inbound `dig.fetchRange` request body.
    pub(crate) fn from_range_request(peer: &'a str, req: &'a Value) -> Self {
        let field = |name: &str| SafeId::new(req.get(name).and_then(Value::as_str).unwrap_or(""));
        ServeTarget {
            peer: SafeId::new(peer),
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
        /// A short, non-sensitive explanation. A [`SafeText`], not a `String`, so the neutralizing
        /// happens at construction however this variant is built (#1609).
        reason: SafeText,
    },
}

impl RangeOutcome {
    /// The node does not hold the requested resource and knows no holder to name.
    pub(crate) fn not_held(code: i64, reason: String) -> Self {
        RangeOutcome::Refused {
            outcome: "not-held",
            code,
            reason: SafeText::new(reason),
        }
    }

    /// The requested offset lies past the end of the resource (an unsatisfiable range).
    pub(crate) fn bad_range(code: i64, reason: String) -> Self {
        RangeOutcome::Refused {
            outcome: "bad-range",
            code,
            reason: SafeText::new(reason),
        }
    }

    /// Name the refusal a catalogued serve error represents: a resource this node does not hold, or
    /// else an unsatisfiable request over one it does. Shared by every path that answers with an error
    /// frame, so the same error code can never be reported under two different outcome names.
    pub(crate) fn from_error(code: i64, message: String) -> Self {
        if code == crate::download::RESOURCE_UNAVAILABLE {
            RangeOutcome::not_held(code, message)
        } else {
            RangeOutcome::bad_range(code, message)
        }
    }

    /// The caller was pointed at other holders instead of being served here — either because this
    /// node lacks the content (#165) or because serving it would exceed its outgoing budget (#30).
    pub(crate) fn redirected(code: i64, reason: String) -> Self {
        RangeOutcome::Refused {
            outcome: "redirect",
            code,
            reason: SafeText::new(reason),
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
/// An UNALIGNED frame has no first chunk index, so the field is OMITTED rather than defaulted: a `0`
/// there would claim the frame starts at chunk 0, which is exactly the falsehood the per-frame metadata
/// contract avoids by omitting what it cannot state truthfully.
pub(crate) fn range_frame_served(offset: usize, bytes: usize, first_chunk_index: Option<u64>) {
    match first_chunk_index {
        Some(index) => tracing::debug!(
            offset,
            bytes,
            first_chunk_index = index,
            chunk_aligned = true,
            "peer serve: dig.fetchRange frame"
        ),
        None => tracing::debug!(
            offset,
            bytes,
            chunk_aligned = false,
            "peer serve: dig.fetchRange frame"
        ),
    }
}

/// Record how an inbound `dig.fetchRange` ended (INFO) — the one line a read diagnosis needs.
///
/// `offset` is always the offset the CALLER REQUESTED, never how far a partial stream advanced: there is
/// exactly one outcome line per request, so it must key to the request the harness greps for. The
/// per-frame DEBUG lines carry the advancing offsets.
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
        store_id = %SafeId::new(store),
        root = %SafeId::new(root.unwrap_or("")),
        retrieval_key = %SafeId::new(retrieval_key.unwrap_or("")),
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

    /// What a target's ids actually render as in a log record.
    fn rendered(target: &ServeTarget<'_>) -> (String, String, String, String) {
        (
            target.peer.to_string(),
            target.store.to_string(),
            target.root.to_string(),
            target.retrieval_key.to_string(),
        )
    }

    #[test]
    fn serve_target_reads_the_canonical_content_ids_off_the_request() {
        let (peer, store, root, rk) = (
            "1c".repeat(32),
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(32),
        );
        let req = json!({"store_id": store, "root": root, "retrieval_key": rk, "offset": 4});
        let target = ServeTarget::from_range_request(&peer, &req);
        assert_eq!(rendered(&target), (peer, store, root, rk));
    }

    #[test]
    fn serve_target_tolerates_a_request_missing_its_ids() {
        // A malformed request still produces a loggable target: the outcome line must never be the
        // thing that fails, or a diagnosis loses the very case it most needs to see.
        let empty = json!({});
        let target = ServeTarget::from_range_request("", &empty);
        assert_eq!(
            rendered(&target),
            (
                ABSENT.to_string(),
                ABSENT.to_string(),
                ABSENT.to_string(),
                ABSENT.to_string()
            )
        );
    }

    #[test]
    fn a_non_canonical_id_renders_as_a_fixed_sentinel_never_verbatim() {
        // The two peer-reachable abuses of a verbatim id, in one predicate: a newline that would end the
        // record and forge another, and bulk that would amplify the log. Both cost a fixed string.
        for hostile in [
            "aa\n  INFO peer serve: dig.fetchRange served outcome=served proof_attached=true",
            &"z".repeat(64 * 1024),
            "not-a-root",
            "../../etc/passwd",
            &format!("{}!", "aa".repeat(32)), // 65 chars: right alphabet, wrong length
        ] {
            let rendered = SafeId::new(hostile).to_string();
            assert_eq!(rendered, NON_CANONICAL, "{hostile:?} must not be echoed");
        }
    }

    #[test]
    fn a_canonical_id_is_logged_in_full_so_no_diagnostic_value_is_lost() {
        let canonical = "9f".repeat(32);
        assert_eq!(SafeId::new(&canonical).to_string(), canonical);
        // Mixed case is still canonical hex — a diagnosis must be able to match what the peer sent.
        let mixed = format!("{}{}", "Ab".repeat(16), "cD".repeat(16));
        assert_eq!(SafeId::new(&mixed).to_string(), mixed);
    }

    /// **Proves:** free-form reason text can neither end a log record nor grow one without bound
    /// (#1603/#1609).
    ///
    /// **Catches:** storing a raw `String` in `Refused`. The payload is the SAME forged-record attack the
    /// id sentinel exists for, arriving through the one field on this surface that has no canonical shape
    /// to check against — so it must be neutralized rather than rejected.
    #[test]
    fn free_form_reason_text_cannot_forge_or_bloat_a_record() {
        let forged = "miss\n  INFO peer serve: dig.fetchRange served outcome=served frames=3";
        let rendered = SafeText::new(forged).to_string();
        assert!(
            !rendered.contains('\n'),
            "a newline would end this record and begin an attacker's: {rendered:?}"
        );
        assert!(
            !rendered.chars().any(char::is_control),
            "CR and ESC forge and rewrite records too, not just LF: {rendered:?}"
        );
        // The text is still READABLE — neutralizing must not cost the diagnosis.
        assert!(rendered.starts_with("miss"));

        // Bounded from BOTH sides of the limit: one over is truncated, and at-bound is untouched.
        let over = "x".repeat(MAX_REASON_CHARS + 1);
        assert_eq!(
            SafeText::new(&over).to_string().chars().count(),
            MAX_REASON_CHARS
        );
        let at_bound = "y".repeat(MAX_REASON_CHARS);
        assert_eq!(SafeText::new(&at_bound).to_string(), at_bound);

        // Substitution is one glyph per character, so the bound still holds for all-control input.
        let controls = "\n".repeat(MAX_REASON_CHARS * 2);
        assert_eq!(
            SafeText::new(&controls).to_string().chars().count(),
            MAX_REASON_CHARS
        );
    }

    /// **Proves:** a refusal built through the crate's REAL constructors carries neutralized text — not
    /// merely that `SafeText` works when called directly (#1609).
    ///
    /// **Catches:** the exact bypass #1609 documents: a wrapper that works in isolation while the type
    /// that owns the field still stores the raw value. Using the real constructors is the point — a test
    /// that hand-built a `Refused` would prove nothing about how the code actually builds one.
    #[test]
    fn every_refusal_constructor_neutralizes_its_reason() {
        let hostile = "boom\nINFO forged outcome=served";
        for outcome in [
            RangeOutcome::not_held(-32004, hostile.into()),
            RangeOutcome::bad_range(-32007, hostile.into()),
            RangeOutcome::redirected(-32008, hostile.into()),
            // The shared dispatcher every error-frame path funnels through.
            RangeOutcome::from_error(-32004, hostile.into()),
            RangeOutcome::from_error(-32007, hostile.into()),
        ] {
            match outcome {
                RangeOutcome::Refused { reason, .. } => assert!(
                    !reason.to_string().contains('\n'),
                    "a refusal built the real way still carried a raw newline"
                ),
                RangeOutcome::Served { .. } => panic!("these constructors build refusals"),
            }
        }
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
