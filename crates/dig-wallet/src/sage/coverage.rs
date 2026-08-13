//! What a completed catch-up actually COVERED, recorded so routing can ask about it.
//!
//! # Why coverage is recorded rather than inferred
//!
//! `initial_sync_complete` is a bare bool: it records THAT a catch-up finished, never WHICH
//! addresses it ran over. Two different sets were therefore being treated as one — the set the
//! catch-up subscribed, and the set the read router calls "ours" — and every attempt to keep them
//! in step by ORDERING two mutations (enrol, then invalidate) left a window:
//!
//! - a catch-up already in flight over `{K1}` completes AFTER `K2` is enrolled and re-latches the
//!   flag over a set it never covered, and
//! - an enrolment that persists the registry and then fails (or dies) before the invalidation
//!   leaves the widened set latched, unrecoverably — the retry enrols nothing and so invalidates
//!   nothing.
//!
//! A recorded covered set removes both by construction. The catch-up writes the set IT ran over, in
//! the same transaction as the flag, so the write cannot describe addresses it did not cover; the
//! router asks whether that recording still CONTAINS the set the node currently follows. Nothing
//! has to happen in the right order, because there is only one write.
//!
//! # Containment, not equality — and therefore fail-closed in one direction only
//!
//! Widening the followed set (enrolling a key) leaves it no longer contained, so every read falls
//! to the chain oracle until a catch-up genuinely covers the new set. The oracle answers
//! truthfully; a stale replica answers a dated zero, and falling to the truthful tier is the
//! correct direction.
//!
//! NARROWING must not invalidate anything, which is why this is containment rather than an equality
//! check on a whole-set fingerprint. `control.wallet.unwatch` removes an address from the followed
//! set; a catch-up that covered the wider set still covers the narrower one, and treating that as
//! stale would force a needless full resync — a self-inflicted outage on a correct operation.
//!
//! Coverage is still asked as ONE question about the WHOLE followed set: an address that is
//! followed but uncovered blinds every read, not only its own. Narrowing that to per-address
//! coverage — so enrolling `K2` need not also send `K1`'s reads to the oracle — is tracked
//! separately (dig_ecosystem#2874).

use chia_protocol::Bytes32;

use super::rpc::normalize_ph;

/// The puzzle-hash set a completed sync actually covered, in the DB's own spelling.
///
/// Canonical by construction: members are normalised through the read router's own
/// [`normalize_ph`], sorted and deduplicated, so a set built from the subscription's `Bytes32`
/// values and one built from an oracle refresh's hex strings compare identically. Serialised as a
/// single comma-separated TEXT column — puzzle hashes are fixed-width lowercase hex, so no member
/// can contain the separator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveredSet(Vec<String>);

impl CoveredSet {
    /// The covered set given its members in any order or spelling.
    pub fn from_hex<I, S>(hashes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut members: Vec<String> = hashes
            .into_iter()
            .map(|h| normalize_ph(h.as_ref()))
            .collect();
        members.sort();
        members.dedup();
        Self(members)
    }

    /// The covered set given the subscription's own puzzle hashes.
    pub fn from_hashes(hashes: &[Bytes32]) -> Self {
        Self::from_hex(hashes.iter().map(hex::encode))
    }

    /// Does this recording cover every address in `followed`?
    ///
    /// The routing question. `true` for a followed set that has NARROWED since the sync (a superset
    /// still covers it) and `false` the moment it WIDENS, which is the whole point.
    pub fn covers(&self, followed: &CoveredSet) -> bool {
        followed.0.iter().all(|ph| self.0.binary_search(ph).is_ok())
    }

    /// The stored spelling.
    pub fn to_storage(&self) -> String {
        self.0.join(",")
    }

    /// Parse a stored spelling. An empty column is the empty set — which covers nothing except an
    /// empty followed set, and so fails closed for any node that follows an address.
    pub fn from_storage(stored: &str) -> Self {
        Self::from_hex(stored.split(',').filter(|m| !m.is_empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ph(byte: u8) -> Bytes32 {
        Bytes32::from([byte; 32])
    }

    /// Catches an implementation that compares the two sides as ordered lists: the catch-up and the
    /// router build the same set from different sources and must still agree.
    #[test]
    fn order_and_duplicates_do_not_change_the_set() {
        let one = CoveredSet::from_hashes(&[ph(1), ph(2), ph(3)]);
        let other = CoveredSet::from_hashes(&[ph(3), ph(2), ph(1), ph(2)]);
        assert_eq!(one, other);
        assert!(one.covers(&other));
    }

    /// Catches an implementation that compares raw spellings: a `0x` prefix or upper-case hex must
    /// not read as a different ADDRESS.
    #[test]
    fn spelling_does_not_change_the_set() {
        let plain = CoveredSet::from_hex(["aabb", "ccdd"]);
        let dressed = CoveredSet::from_hex(["0xAABB", "CCDD"]);
        assert_eq!(plain, dressed);
        assert!(plain.covers(&dressed));
    }

    /// THE F1/F2 PROPERTY. Catches any implementation that treats a completed sync as covering
    /// whatever the node happens to follow now — including the whole class of fixes that keep a
    /// bare flag and try to invalidate it by a second, separately-ordered write.
    #[test]
    fn a_widened_followed_set_is_not_covered() {
        let covered = CoveredSet::from_hashes(&[ph(1)]);
        let widened = CoveredSet::from_hashes(&[ph(1), ph(2)]);
        assert!(!covered.covers(&widened));
    }

    /// THE NARROWING PROPERTY. Catches an equality check (a whole-set fingerprint compared with
    /// `==`), under which `control.wallet.unwatch` would invalidate a catch-up that genuinely
    /// covers the remaining addresses and force a needless full resync.
    #[test]
    fn a_narrowed_followed_set_stays_covered() {
        let covered = CoveredSet::from_hashes(&[ph(1), ph(2)]);
        let narrowed = CoveredSet::from_hashes(&[ph(1)]);
        assert!(covered.covers(&narrowed));
    }

    /// Catches a storage round-trip that loses or reorders members — the stored value is what a
    /// restart routes on, so a lossy encoding would silently un-cover a synced replica.
    #[test]
    fn storage_round_trips() {
        let covered = CoveredSet::from_hashes(&[ph(9), ph(1), ph(5)]);
        assert_eq!(CoveredSet::from_storage(&covered.to_storage()), covered);
        // A pre-#2871 replica's column arrives empty: it covers no address at all.
        let empty = CoveredSet::from_storage("");
        assert!(!empty.covers(&CoveredSet::from_hashes(&[ph(1)])));
        assert!(empty.covers(&CoveredSet::from_hashes(&[])));
    }
}
