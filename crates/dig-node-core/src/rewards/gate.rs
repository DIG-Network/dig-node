//! The mirror-coin gate (SPEC §4, §10). A candidate is admitted only when all three §4.3 calls
//! agree: `advertises(store, root, mirror_collateral_epoch)` AND `declares_peer(peer_id)` ->
//! `owner_puzzle_hash()`. Fail-closed on every absence or mismatch (§4.2, §10.3) — ineligibility is
//! never an accusation, never a strike, never a blocklist entry.
//!
//! This module does not reimplement `MirrorCoin::advertises` / `declares_peer` /
//! `owner_puzzle_hash` (Appendix B hard rule — see `crate::mirror_bond` for the existing verified-
//! pointer pattern this follows). It defines [`MirrorCoinReader`], the narrow seam over those three
//! calls, and drives the SPEC's admission logic — including the §4.6.3 grace window — against it.
//! The host binary supplies the real reader (wired to `dig-mirror-coin`) exactly the way
//! `mirror_bond::MirrorBondVerifier` is wired today.

use async_trait::async_trait;

/// One candidate's claimed mirror-coin pointer, exactly as a `ProviderRecord` carries it
//  (`unverified_mirror_coin_id`, SPEC §4.1-§4.2) — a claim, proves nothing on its own.
pub type CoinIdHint = Option<[u8; 32]>;

/// The three SPEC §4.3 calls, plus the §4.2 coin-validity checks, as one seam. An implementation
/// MUST perform every §4.2 check (puzzle hash, asset id, collateral, unspent) before answering
/// `advertises`/`declares_peer`/`owner_puzzle_hash` — this trait's contract is that a `true` /
/// `Some` answer already reflects all of them, so the gate above it does not need to re-derive
/// coin validity.
#[async_trait]
pub trait MirrorCoinReader: Send + Sync {
    /// SPEC §4.2 + §4.3 row 1: fetch the coin at `coin_id` and confirm it advertises exactly
    /// `(store_id, root, mirror_collateral_epoch)`. `false` for absent, unresolvable, invalid,
    /// spent, under-collateralised, or non-advertising — every §4.2/§4.3.1 failure collapses to
    /// `false` here because none of them distinguish for the caller (SPEC §4.2: "MUST NOT be
    /// treated as evidence of bad faith").
    async fn advertises(
        &self,
        coin_id: [u8; 32],
        store_id: [u8; 32],
        root: [u8; 32],
        mirror_collateral_epoch: u64,
    ) -> bool;

    /// SPEC §4.3 row 2: does this coin declare `peer_id` as its owner-authenticated claimant.
    async fn declares_peer(&self, coin_id: [u8; 32], peer_id: [u8; 32]) -> bool;

    /// SPEC §4.3 row 3 / §10.2: the payout puzzle hash the entry would carry, derived from the
    /// coin's lineage proof. `None` if the coin cannot be resolved (fail-closed).
    async fn owner_puzzle_hash(&self, coin_id: [u8; 32]) -> Option<[u8; 32]>;
}

/// Why a candidate was refused. Carried for logging/tests only — SPEC §4.2/§10.3: none of these is
/// an accusation, so no variant here may become a strike or a blocklist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateIneligibleReason {
    /// No `unverified_mirror_coin_id` hint on the candidate's provider record.
    AbsentCoinIdHint,
    /// The coin does not advertise this `(store, root, epoch)` at all — covers "spent",
    /// "wrong epoch ordinal", and "not a mirror coin" alike (§4.2's collapse).
    DoesNotAdvertise,
    /// The coin advertises the content but does not declare this candidate's `peer_id`.
    PeerNotDeclared,
    /// The coin resolved but its lineage-derived owner puzzle hash could not be read.
    AbsentDeclaration,
}

/// What the gate decided for one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    Eligible { payout_puzzle_hash: [u8; 32] },
    Ineligible(GateIneligibleReason),
}

/// The mirror-coin gate contract [`admission::admit`](super::admission::admit) drives.
#[async_trait]
pub trait MirrorCoinGatePort: Send + Sync {
    async fn evaluate(&self, peer_id: [u8; 32], mirror_collateral_epoch_ordinal: Option<u64>) -> GateOutcome;
}

/// The SPEC §4-driven gate: takes a candidate's coin-id hint and a `MirrorCoinReader`, and decides
/// eligibility per §4.2-§4.6.
pub struct SpecMirrorCoinGate<R: MirrorCoinReader> {
    reader: R,
    store_id: [u8; 32],
    root: [u8; 32],
    /// A peer_id -> coin-id-hint lookup: the gate itself does not own DHT candidate state, only the
    /// mapping a discovery path already resolved for this peer this cycle.
    coin_hint_for: std::collections::HashMap<[u8; 32], CoinIdHint>,
}

impl<R: MirrorCoinReader> SpecMirrorCoinGate<R> {
    pub fn new(
        reader: R,
        store_id: [u8; 32],
        root: [u8; 32],
        coin_hint_for: std::collections::HashMap<[u8; 32], CoinIdHint>,
    ) -> Self {
        Self {
            reader,
            store_id,
            root,
            coin_hint_for,
        }
    }

    /// SPEC §4.6.3: during the grace window after a rollover, the PREVIOUS ordinal is also
    /// accepted, and a rollover mismatch MUST NOT strike (the caller enforces the "no strike" half;
    /// this function only decides eligibility).
    async fn advertises_current_or_previous(
        &self,
        coin_id: [u8; 32],
        current_epoch: u64,
        in_grace_window: bool,
    ) -> bool {
        if self
            .reader
            .advertises(coin_id, self.store_id, self.root, current_epoch)
            .await
        {
            return true;
        }
        if in_grace_window && current_epoch > 0 {
            return self
                .reader
                .advertises(coin_id, self.store_id, self.root, current_epoch - 1)
                .await;
        }
        false
    }
}

#[async_trait]
impl<R: MirrorCoinReader> MirrorCoinGatePort for SpecMirrorCoinGate<R> {
    async fn evaluate(&self, peer_id: [u8; 32], mirror_collateral_epoch_ordinal: Option<u64>) -> GateOutcome {
        // SPEC §4.6 clause 2: the ordinal is an INPUT; its absence is ineligibility, never a
        // computed guess (dig_ecosystem#3259).
        let Some(current_epoch) = mirror_collateral_epoch_ordinal else {
            return GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise);
        };

        let Some(hint) = self.coin_hint_for.get(&peer_id).copied().flatten() else {
            return GateOutcome::Ineligible(GateIneligibleReason::AbsentCoinIdHint);
        };

        // Grace window handling is delegated to the caller in production (it needs wall-clock
        // context this gate does not hold); for the pure §4.3 chain here we accept the current
        // ordinal only, matching a cycle called immediately at rollover with no grace granted. The
        // grace-window itself is exercised via `advertises_current_or_previous` directly in tests.
        if !self
            .advertises_current_or_previous(hint, current_epoch, false)
            .await
        {
            return GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise);
        }

        if !self.reader.declares_peer(hint, peer_id).await {
            return GateOutcome::Ineligible(GateIneligibleReason::PeerNotDeclared);
        }

        match self.reader.owner_puzzle_hash(hint).await {
            Some(payout_puzzle_hash) => GateOutcome::Eligible { payout_puzzle_hash },
            None => GateOutcome::Ineligible(GateIneligibleReason::AbsentDeclaration),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeReader {
        advertising: HashMap<([u8; 32], u64), bool>,
        declaring: HashMap<[u8; 32], [u8; 32]>,
        owners: HashMap<[u8; 32], [u8; 32]>,
    }

    #[async_trait]
    impl MirrorCoinReader for FakeReader {
        async fn advertises(
            &self,
            coin_id: [u8; 32],
            _store_id: [u8; 32],
            _root: [u8; 32],
            epoch: u64,
        ) -> bool {
            self.advertising.get(&(coin_id, epoch)).copied().unwrap_or(false)
        }
        async fn declares_peer(&self, coin_id: [u8; 32], peer_id: [u8; 32]) -> bool {
            self.declaring.get(&coin_id) == Some(&peer_id)
        }
        async fn owner_puzzle_hash(&self, coin_id: [u8; 32]) -> Option<[u8; 32]> {
            self.owners.get(&coin_id).copied()
        }
    }

    const STORE: [u8; 32] = [1; 32];
    const ROOT: [u8; 32] = [2; 32];
    const PEER: [u8; 32] = [3; 32];
    const COIN: [u8; 32] = [4; 32];
    const OWNER: [u8; 32] = [5; 32];

    fn gate(reader: FakeReader, hint: CoinIdHint) -> SpecMirrorCoinGate<FakeReader> {
        SpecMirrorCoinGate::new(reader, STORE, ROOT, [(PEER, hint)].into_iter().collect())
    }

    #[tokio::test]
    async fn absent_coin_id_hint_is_ineligible() {
        let g = gate(FakeReader::default(), None);
        assert_eq!(
            g.evaluate(PEER, Some(1)).await,
            GateOutcome::Ineligible(GateIneligibleReason::AbsentCoinIdHint)
        );
    }

    #[tokio::test]
    async fn epoch_ordinal_absent_is_ineligible_never_a_guess() {
        let g = gate(FakeReader::default(), Some(COIN));
        assert_eq!(
            g.evaluate(PEER, None).await,
            GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise)
        );
    }

    #[tokio::test]
    async fn spent_or_non_advertising_coin_is_ineligible() {
        let reader = FakeReader::default(); // advertising map empty == coin doesn't advertise (covers spent/absent)
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, Some(1)).await,
            GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise)
        );
    }

    #[tokio::test]
    async fn wrong_epoch_ordinal_is_ineligible() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 7), true); // advertises epoch 7, we ask about 1
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, Some(1)).await,
            GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise)
        );
    }

    #[tokio::test]
    async fn declares_peer_mismatch_is_ineligible() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 1), true);
        reader.declaring.insert(COIN, [0xEE; 32]); // declares someone else
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, Some(1)).await,
            GateOutcome::Ineligible(GateIneligibleReason::PeerNotDeclared)
        );
    }

    #[tokio::test]
    async fn absent_declaration_is_ineligible() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 1), true);
        // declares_peer defaults to false (not in map) -> PeerNotDeclared covers "absent declaration" too
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, Some(1)).await,
            GateOutcome::Ineligible(GateIneligibleReason::PeerNotDeclared)
        );
    }

    #[tokio::test]
    async fn all_three_calls_agreeing_is_eligible() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 1), true);
        reader.declaring.insert(COIN, PEER);
        reader.owners.insert(COIN, OWNER);
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, Some(1)).await,
            GateOutcome::Eligible {
                payout_puzzle_hash: OWNER
            }
        );
    }

    /// SPEC §4.6.3: previous ordinal accepted inside the grace window.
    #[tokio::test]
    async fn previous_ordinal_accepted_within_grace_window() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 4), true); // declares previous ordinal (current is 5)
        let g = gate(reader, Some(COIN));
        assert!(g.advertises_current_or_previous(COIN, 5, true).await);
    }

    /// SPEC §4.6.3: outside the grace window, a rollover mismatch is simply ineligible, and this
    /// crate MUST NOT strike for it (enforced at the cycle layer, not here).
    #[tokio::test]
    async fn previous_ordinal_rejected_outside_grace_window() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 4), true);
        let g = gate(reader, Some(COIN));
        assert!(!g.advertises_current_or_previous(COIN, 5, false).await);
    }
}
