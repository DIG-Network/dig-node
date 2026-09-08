//! The mirror-coin gate (SPEC §4, §10). A candidate is admitted only when all three §4.3 calls
//! agree: `advertises(store, root, census_epoch)` AND `declares_peer(peer_id)` ->
//! `owner_puzzle_hash()`. Fail-closed on every absence or mismatch (§4.2, §10.3) — ineligibility is
//! never an accusation, never a strike, never a blocklist entry.
//!
//! This module does not reimplement `MirrorCoin::advertises` / `declares_peer` /
//! `owner_puzzle_hash` (Appendix B hard rule — see `crate::mirror_bond` for the existing verified-
//! pointer pattern this follows). It defines [`MirrorCoinReader`], the narrow seam over those three
//! calls, and drives the SPEC's admission logic — including the §4.6 census offset and the §4.6.3
//! grace window — against it. The host binary supplies the real reader (wired to `dig-mirror-coin`)
//! exactly the way `mirror_bond::MirrorBondVerifier` is wired today.

use super::spec_constants::MIRROR_EPOCH_GRACE_SECONDS;
use async_trait::async_trait;

/// One candidate's claimed mirror-coin pointer, exactly as a `ProviderRecord` carries it
//  (`unverified_mirror_coin_id`, SPEC §4.1-§4.2) — a claim, proves nothing on its own.
pub type CoinIdHint = Option<[u8; 32]>;

/// The mirror-collateral epoch context needed to evaluate one peer this cycle (SPEC §4.6).
///
/// `current_epoch` is the mirror-collateral epoch ordinal currently open (`n`), supplied by the
/// caller as CONFIGURATION — this gate never computes or guesses it (SPEC §4.6 clause 2,
/// DIG-Network/dig_ecosystem#3259: nobody owns the calendar yet). Its absence is a PROVER-side
/// fault, not a peer-attributable one — see [`GateError::EpochOrdinalUnavailable`].
#[derive(Debug, Clone, Copy)]
pub struct EpochContext {
    pub current_epoch: Option<u64>,
    /// Wall-clock unix seconds the CURRENT epoch rolled over at, if known. `None` = no rollover
    /// tracked (e.g. first epoch observed), so no grace applies.
    pub epoch_rolled_over_at: Option<u64>,
    /// Now, from the caller's injected `Clock` — used only to decide whether we're still inside
    /// the SPEC §4.6.3 grace window.
    pub now: u64,
}

impl EpochContext {
    fn in_grace_window(&self) -> bool {
        match self.epoch_rolled_over_at {
            Some(rolled_at) => self.now.saturating_sub(rolled_at) < MIRROR_EPOCH_GRACE_SECONDS,
            None => false,
        }
    }
}

/// The three SPEC §4.3 calls, plus the §4.2 coin-validity checks, as one seam. An implementation
/// MUST perform every §4.2 check (puzzle hash, asset id, collateral, unspent) before answering
/// `advertises`/`declares_peer`/`owner_puzzle_hash` — this trait's contract is that a `true` /
/// `Some` answer already reflects all of them, so the gate above it does not need to re-derive
/// coin validity.
#[async_trait]
pub trait MirrorCoinReader: Send + Sync {
    /// SPEC §4.2 + §4.3 row 1: fetch the coin at `coin_id` and confirm it advertises exactly
    /// `(store_id, root, census_epoch)`. `false` for absent, unresolvable, invalid, spent,
    /// under-collateralised, or non-advertising — every §4.2/§4.3.1 failure collapses to `false`
    /// here because none of them distinguish for the caller (SPEC §4.2: "MUST NOT be treated as
    /// evidence of bad faith").
    async fn advertises(
        &self,
        coin_id: [u8; 32],
        store_id: [u8; 32],
        root: [u8; 32],
        census_epoch: u64,
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
    /// The coin does not advertise this `(store, root, census_epoch)` at all — covers "spent",
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

/// Why the gate could not evaluate ANY candidate this cycle — a prover-side fault, never a
/// peer-attributable ineligibility. Deliberately NOT a `GateIneligibleReason` variant: a caller
/// that could construct this as ordinary ineligibility would strike the peer for a configuration
/// gap that is not its fault (SPEC §3.6 clause 4 / dig_ecosystem#3250 D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    /// SPEC §4.6 clause 2 / dig_ecosystem#3259: the mirror-collateral epoch ordinal was not
    /// supplied. The caller MUST map this to `ProverState::ChainSourceUnavailable`, abort the
    /// cycle WITHOUT evaluating any candidate, and MUST NOT increment any peer's strike counter.
    EpochOrdinalUnavailable,
}

/// The mirror-coin gate contract [`admission::admit`](super::admission::admit) drives.
#[async_trait]
pub trait MirrorCoinGatePort: Send + Sync {
    async fn evaluate(&self, peer_id: [u8; 32], ctx: EpochContext) -> Result<GateOutcome, GateError>;
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

    /// SPEC §4.6.3: during the grace window after a rollover, the PREVIOUS census ordinal is also
    /// accepted, and a rollover mismatch MUST NOT strike (the caller enforces the "no strike" half;
    /// this function only decides eligibility). `census_epoch` is already the §4.6.1 offset
    /// (`current_epoch - 1`) — see [`Self::census_epoch`].
    pub async fn advertises_current_or_previous(
        &self,
        coin_id: [u8; 32],
        census_epoch: u64,
        in_grace_window: bool,
    ) -> bool {
        if self
            .reader
            .advertises(coin_id, self.store_id, self.root, census_epoch)
            .await
        {
            return true;
        }
        if in_grace_window && census_epoch > 0 {
            return self
                .reader
                .advertises(coin_id, self.store_id, self.root, census_epoch - 1)
                .await;
        }
        false
    }
}

#[async_trait]
impl<R: MirrorCoinReader> MirrorCoinGatePort for SpecMirrorCoinGate<R> {
    async fn evaluate(&self, peer_id: [u8; 32], ctx: EpochContext) -> Result<GateOutcome, GateError> {
        // SPEC §4.6 clause 2 / D5: the ordinal is an INPUT; its absence is a PROVER fault
        // (ChainSourceUnavailable at the cycle layer), never guessed and never peer-attributable
        // ineligibility (dig_ecosystem#3259, #3250 D5).
        let Some(current_epoch) = ctx.current_epoch else {
            return Err(GateError::EpochOrdinalUnavailable);
        };

        // SPEC §4.6.1: a coin qualifies for the census of epoch `n` only by declaring `n-1`
        // EXACTLY. `n == 0` means no epoch has closed a census round yet — nothing can qualify.
        let Some(census_epoch) = current_epoch.checked_sub(1) else {
            return Ok(GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise));
        };

        let Some(hint) = self.coin_hint_for.get(&peer_id).copied().flatten() else {
            return Ok(GateOutcome::Ineligible(GateIneligibleReason::AbsentCoinIdHint));
        };

        if !self
            .advertises_current_or_previous(hint, census_epoch, ctx.in_grace_window())
            .await
        {
            return Ok(GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise));
        }

        if !self.reader.declares_peer(hint, peer_id).await {
            return Ok(GateOutcome::Ineligible(GateIneligibleReason::PeerNotDeclared));
        }

        match self.reader.owner_puzzle_hash(hint).await {
            Some(payout_puzzle_hash) => Ok(GateOutcome::Eligible { payout_puzzle_hash }),
            None => Ok(GateOutcome::Ineligible(GateIneligibleReason::AbsentDeclaration)),
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

    fn ctx(current_epoch: Option<u64>) -> EpochContext {
        EpochContext {
            current_epoch,
            epoch_rolled_over_at: None,
            now: 0,
        }
    }

    #[tokio::test]
    async fn absent_coin_id_hint_is_ineligible() {
        let g = gate(FakeReader::default(), None);
        assert_eq!(
            g.evaluate(PEER, ctx(Some(2))).await,
            Ok(GateOutcome::Ineligible(GateIneligibleReason::AbsentCoinIdHint))
        );
    }

    /// D5: an absent epoch ordinal is a PROVER-side fault, never `GateIneligibleReason` — it must
    /// come back as `Err`, not as an eligibility verdict a caller could strike a peer over.
    #[tokio::test]
    async fn epoch_ordinal_absent_is_a_gate_error_not_an_ineligibility_verdict() {
        let g = gate(FakeReader::default(), Some(COIN));
        assert_eq!(
            g.evaluate(PEER, ctx(None)).await,
            Err(GateError::EpochOrdinalUnavailable)
        );
    }

    #[tokio::test]
    async fn current_epoch_zero_has_no_closed_census_and_is_ineligible() {
        let g = gate(FakeReader::default(), Some(COIN));
        assert_eq!(
            g.evaluate(PEER, ctx(Some(0))).await,
            Ok(GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise))
        );
    }

    #[tokio::test]
    async fn spent_or_non_advertising_coin_is_ineligible() {
        let reader = FakeReader::default(); // advertising map empty == coin doesn't advertise (covers spent/absent)
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, ctx(Some(2))).await,
            Ok(GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise))
        );
    }

    /// D1 regression: declaring the CURRENT epoch ordinal `n` directly must NOT qualify the
    /// census of epoch `n` — only `n-1` does (SPEC §4.6.1). This fails on the pre-fix code, which
    /// queried `advertises(.., current_epoch)` instead of `current_epoch - 1`.
    #[tokio::test]
    async fn census_epoch_is_n_minus_1_not_n() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 5), true); // declares n=5 itself, not n-1=4
        reader.declaring.insert(COIN, PEER);
        reader.owners.insert(COIN, OWNER);
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, ctx(Some(5))).await,
            Ok(GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise)),
            "declaring n directly must NOT qualify the census of epoch n (SPEC §4.6.1)"
        );
    }

    /// D1 positive: declaring exactly `n-1` for current epoch `n` DOES qualify.
    #[tokio::test]
    async fn census_epoch_n_minus_1_is_admitted() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 4), true); // n-1 = 4 for current epoch n=5
        reader.declaring.insert(COIN, PEER);
        reader.owners.insert(COIN, OWNER);
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, ctx(Some(5))).await,
            Ok(GateOutcome::Eligible {
                payout_puzzle_hash: OWNER
            })
        );
    }

    #[tokio::test]
    async fn declares_peer_mismatch_is_ineligible() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 1), true); // census epoch 1 (current epoch 2)
        reader.declaring.insert(COIN, [0xEE; 32]); // declares someone else
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, ctx(Some(2))).await,
            Ok(GateOutcome::Ineligible(GateIneligibleReason::PeerNotDeclared))
        );
    }

    /// D3: exercises the `owner_puzzle_hash() == None` path, distinct from `PeerNotDeclared`.
    #[tokio::test]
    async fn absent_declaration_is_ineligible() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 1), true); // census epoch 1 (current epoch 2)
        reader.declaring.insert(COIN, PEER);
        // owners map has no entry for COIN -> owner_puzzle_hash() resolves to None.
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, ctx(Some(2))).await,
            Ok(GateOutcome::Ineligible(GateIneligibleReason::AbsentDeclaration))
        );
    }

    #[tokio::test]
    async fn all_three_calls_agreeing_is_eligible() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 1), true); // census epoch 1 (current epoch 2)
        reader.declaring.insert(COIN, PEER);
        reader.owners.insert(COIN, OWNER);
        let g = gate(reader, Some(COIN));
        assert_eq!(
            g.evaluate(PEER, ctx(Some(2))).await,
            Ok(GateOutcome::Eligible {
                payout_puzzle_hash: OWNER
            })
        );
    }

    /// SPEC §4.6.3: previous census ordinal accepted inside the grace window — reachable through
    /// `evaluate`, not only through the private helper (D2 regression).
    #[tokio::test]
    async fn grace_window_makes_previous_census_ordinal_admissible_via_evaluate() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 4), true); // pre-rollover census ordinal
        reader.declaring.insert(COIN, PEER);
        reader.owners.insert(COIN, OWNER);
        let g = gate(reader, Some(COIN));
        let inside_grace = EpochContext {
            current_epoch: Some(6), // census would need 5; coin still shows 4
            epoch_rolled_over_at: Some(1_000),
            now: 1_000 + MIRROR_EPOCH_GRACE_SECONDS - 1,
        };
        assert_eq!(
            g.evaluate(PEER, inside_grace).await,
            Ok(GateOutcome::Eligible {
                payout_puzzle_hash: OWNER
            })
        );
    }

    /// D2 regression: outside the grace window the same mismatch is simply ineligible (never a
    /// strike — enforced at the cycle layer).
    #[tokio::test]
    async fn outside_grace_window_previous_census_ordinal_is_rejected() {
        let mut reader = FakeReader::default();
        reader.advertising.insert((COIN, 4), true);
        reader.declaring.insert(COIN, PEER);
        reader.owners.insert(COIN, OWNER);
        let g = gate(reader, Some(COIN));
        let outside_grace = EpochContext {
            current_epoch: Some(6),
            epoch_rolled_over_at: Some(1_000),
            now: 1_000 + MIRROR_EPOCH_GRACE_SECONDS + 1,
        };
        assert_eq!(
            g.evaluate(PEER, outside_grace).await,
            Ok(GateOutcome::Ineligible(GateIneligibleReason::DoesNotAdvertise))
        );
    }
}
