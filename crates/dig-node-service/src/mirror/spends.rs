//! [`MirrorSpends`] — the type that bounds what the automatic signer is able to sign.
//!
//! # Why a type and not a check
//!
//! The user cannot approve each mirror-coin spend, so the node signs them itself. What makes that
//! defensible is that the authority is *narrow*: this key can create a mirror coin and reclaim one,
//! and nothing else. A narrow authority enforced by an `if` inside the signer is only as narrow as
//! every future caller remembers to keep it — and a signer that accepts a `Vec<CoinSpend>` and
//! inspects it is a general-purpose signing oracle with a filter in front, one refactor away from
//! being a general-purpose signing oracle.
//!
//! So the constraint is the argument type. [`MirrorSpends`] has no public constructor, no
//! `Default`, and no way to be built from arbitrary spends. The only two producers are in this
//! module, and each is a thin wrapper over the corresponding `dig_mirror_coin` builder. The signer
//! ([`super::signer::MirrorSigner::sign`]) takes one and nothing else will type-check.
//!
//! That is a compile-time property of the API surface rather than a claim about its behaviour: to
//! widen the authority you would have to add a producer here, which is a visible, reviewable edit to
//! a file whose entire purpose is to say what may be signed.
//!
//! # The spend bundles are never hand-rolled
//!
//! Both producers delegate to `dig_mirror_coin`, which owns the puzzle, the CAT construction and the
//! memo layout. Nothing in dig-node assembles a mirror spend itself (§4.1).

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_sdk_driver::{Cat, StandardLayer};
use clvm_utils::ToTreeHash;
use dig_mirror_coin::{MirrorAdvertisement, MirrorCoin, MirrorError};
use num_bigint::BigInt;

use crate::spend_audit::{kinds, Asset, AuditedBond, Authority, SpendIntent, SpendKind};

/// What a mirror spend is FOR. Carried alongside the spends so the audit entry and any log can name
/// the operation without re-deriving it from the CLVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorOperation {
    /// Locking collateral to advertise a `(store, root, epoch)`.
    Create,
    /// Releasing collateral back to its owner.
    Reclaim,
}

impl MirrorOperation {
    /// A stable token for the audit record and for logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            MirrorOperation::Create => "create",
            MirrorOperation::Reclaim => "reclaim",
        }
    }
}

/// Coin spends that are PROVEN to be a mirror-coin create or reclaim, because the only way to build
/// one is through this module.
///
/// Holding one is the permission the automatic signer requires. There is deliberately no
/// `from_coin_spends`, no `push`, and no field access that would let a caller assemble the inside of
/// one by hand.
#[derive(Debug, Clone)]
pub struct MirrorSpends {
    operation: MirrorOperation,
    spends: Vec<CoinSpend>,
    fee_mojos: u64,
    owner_puzzle_hash: Bytes32,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: BigInt,
    collateral_dig_base_units: u64,
}

impl MirrorSpends {
    /// Which operation these spends perform.
    pub fn operation(&self) -> MirrorOperation {
        self.operation
    }

    /// The spends, for signing and broadcast. Read-only: a caller can look at them and cannot add to
    /// them, so a borrowed `MirrorSpends` cannot become a vehicle for an unrelated spend.
    pub fn coin_spends(&self) -> &[CoinSpend] {
        &self.spends
    }

    /// The XCH fee, in mojos, that these spends actually pay.
    ///
    /// Recorded at build time from the same `fee` handed to the `dig_mirror_coin` builder, so it
    /// describes the artifact rather than a caller's account of it. That distinction is the whole
    /// value of the field: `MirrorSigner::sign` bounds THIS against
    /// [`MIRROR_SPEND_FEE_CEILING_MOJOS`](super::signer::MIRROR_SPEND_FEE_CEILING_MOJOS), and a fee
    /// supplied to the signer separately would have been a number about the bundle instead of the
    /// bundle's own — bypassable by any caller that passed a different one, with no edit to the
    /// signer. It is also the figure §25.2 requires in the audit entry.
    pub fn fee_mojos(&self) -> u64 {
        self.fee_mojos
    }

    /// The puzzle hash these spends belong to — the key a create was built for, or the on-chain
    /// owner of the coin a reclaim releases.
    ///
    /// `MirrorSigner::sign` refuses any bundle whose owner is not its own wallet's. Without it,
    /// §25.2's destination bound would rest on every call site having passed the right key: the
    /// builders take a `synthetic_key` while the signer signs with `self.wallet`, and nothing
    /// related the two. The failure direction was safe — the network rejects the mismatch — but
    /// "the network catches it" is not the same guarantee as "it cannot be built", and this module's
    /// thesis is the second one.
    pub fn owner_puzzle_hash(&self) -> Bytes32 {
        self.owner_puzzle_hash
    }

    /// The audit intent these spends imply, derived wholly from the spends themselves.
    ///
    /// This is deliberately not something a caller supplies. An intent passed ALONGSIDE the spends
    /// is a claim about them: it can name a different amount, a different store, or a different fee
    /// than the bundle actually moves, and the resulting record is confidently wrong — which is
    /// worse than no record, because §908's carve-out is bought precisely with the record being
    /// true. Deriving it here makes the two unable to disagree.
    pub(crate) fn intent(&self) -> SpendIntent {
        SpendIntent {
            kind: SpendKind::new(kinds::MIRROR_COIN),
            purpose: format!(
                "{} a mirror coin for store {} at root {} in epoch {}",
                self.operation.as_str(),
                hex::encode(self.store_launcher_id),
                hex::encode(self.root_hash),
                self.epoch,
            ),
            authority: Authority {
                principal: "node".to_string(),
                grant: "mirror-collateral".to_string(),
            },
            asset: Asset::Dig,
            amount_mojos: self.collateral_dig_base_units,
            fee_mojos: self.fee_mojos,
            store_id: Some(hex::encode(self.store_launcher_id)),
            // The other two thirds of the bond key, recorded structurally rather than left to be
            // read back out of `purpose`. This is what lets a pass that has just restarted tell
            // which `(store, root, epoch)` create is already in flight (SPEC.md 25.4.6) without
            // remembering anything itself.
            // The mirror epoch is a `BigInt` on the wire because the hint morph is arithmetic over
            // 32-byte values. As a NUMBER it is a wall-clock round index and fits an i64 for the
            // next few hundred million years. One that does not fit yields `None` rather than a
            // truncated epoch: `None` suppresses nothing, whereas a wrong epoch would suppress the
            // WRONG create, and a bond left uncollateralised is worse than one attempted twice.
            bond: i64::try_from(self.epoch.clone())
                .ok()
                .map(|epoch| AuditedBond {
                    root: hex::encode(self.root_hash),
                    epoch,
                }),
        }
    }
}

/// Build the spends that lock `collateral_dig_base_units` of $DIG as a mirror for one `(store, root,
/// epoch)`.
///
/// A thin wrapper over `dig_mirror_coin::create`: it adds no conditions, alters no amount, and
/// changes no destination. Its whole contribution is that what comes back is a [`MirrorSpends`],
/// which is the thing the signer will accept.
///
/// `collateral_dig_base_units` is $DIG in **base units** (1 DIG = 1_000), and it is the CURRENT
/// epoch's derived requirement — `apply_safety_margin(required_per_store, margin_bp)` (`SPEC.md`
/// §25.3) — never a constant. Passing a whole-$DIG figure would lock a thousandth of the intended
/// amount and still look like a successful advertisement, which is why the parameter name carries
/// its unit.
#[allow(clippy::too_many_arguments)]
pub fn build_create(
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: BigInt,
    urls: Vec<String>,
    collateral_dig_base_units: u64,
    dig_coins: Vec<Cat>,
    synthetic_key: PublicKey,
    fee_coins: Vec<Coin>,
    fee: u64,
) -> Result<MirrorSpends, MirrorError> {
    let spends = dig_mirror_coin::create(
        MirrorAdvertisement {
            store_launcher_id,
            root_hash,
            epoch: epoch.clone(),
            urls,
            // No peer declaration: this reproduces exactly what dig-mirror-coin 0.7 wrote, which
            // had no declared_peer concept at all, so the bump changes nothing about the coins this
            // node creates. It is a deliberate choice rather than a default -- the crate made the
            // field required precisely so a consumer cannot inherit one silently. Binding this
            // collateral to the node's own DIG peer id is dig-node#473, which owns that decision and
            // the signature change it needs.
            declared_peer: None,
            collateral: collateral_dig_base_units,
        },
        dig_coins,
        synthetic_key,
        fee_coins,
        fee,
    )?;

    Ok(MirrorSpends {
        operation: MirrorOperation::Create,
        spends,
        fee_mojos: fee,
        // Re-derived from the key the spends were built for, by the same standard derivation
        // `dig_mirror_coin::reclaim` uses to decide ownership — so the recorded owner is a property
        // of the bundle rather than a second thing a caller could state.
        owner_puzzle_hash: StandardLayer::new(synthetic_key).tree_hash().into(),
        store_launcher_id,
        root_hash,
        epoch,
        collateral_dig_base_units,
    })
}

/// Build the spends that release `mirror`'s collateral back to its owner.
///
/// A thin wrapper over `dig_mirror_coin::reclaim`, which recreates the full locked amount at the
/// owner's own puzzle hash. There is no supply-reducing path in that crate and none is added here:
/// reclaim returns the money, and an operation that destroyed it would be a different function with
/// a different name.
///
/// `fee` may be zero, and a zero-fee reclaim is supported. That matters: a node whose XCH is
/// exhausted must still be able to recover $DIG it has locked, which is precisely what the legacy
/// could not do.
pub fn build_reclaim(
    mirror: &MirrorCoin,
    synthetic_key: PublicKey,
    fee_coins: Vec<Coin>,
    fee: u64,
) -> Result<MirrorSpends, MirrorError> {
    let spends = dig_mirror_coin::reclaim(mirror, synthetic_key, fee_coins, fee)?;

    Ok(MirrorSpends {
        operation: MirrorOperation::Reclaim,
        spends,
        fee_mojos: fee,
        // The coin's own owner, read from its lineage proof rather than from the caller. `reclaim`
        // has already refused (`NotOwner`) any coin this key does not own, so by the time there are
        // spends at all these two agree.
        owner_puzzle_hash: mirror.owner_puzzle_hash(),
        store_launcher_id: mirror.store_launcher_id(),
        root_hash: mirror.root_hash(),
        epoch: mirror.epoch().clone(),
        // What the coin actually locked, which is exactly what a reclaim returns -- not the current
        // epoch's requirement. A coin bonded under a previous epoch's amount is reclaimed at that
        // amount (SPEC.md 25.3).
        collateral_dig_base_units: mirror.collateral(),
    })
}

/// An empty [`MirrorSpends`] for tests that exercise the SIGNER rather than the builders.
///
/// `#[cfg(test)]` so it cannot become a production constructor — the no-public-constructor property
/// is the whole authority bound, and a test seam that widened it would quietly remove the thing this
/// module exists to guarantee. It carries [`MirrorOperation::Create`] because a `MirrorSpends` always
/// names an operation; the operation is irrelevant to an empty spend set.
///
/// `fee_mojos` and `owner_puzzle_hash` are parameters rather than fixed values so a signer test can
/// exercise the ceiling and the wallet binding without a chain. They are the two things about these
/// spends the signer reads, and a fixture that could not vary them could not test either bound: a
/// double that can only hold one value cannot express the disagreement being guarded against.
#[cfg(test)]
pub(crate) fn empty_for_tests(fee_mojos: u64, owner_puzzle_hash: Bytes32) -> MirrorSpends {
    MirrorSpends {
        operation: MirrorOperation::Create,
        spends: Vec::new(),
        fee_mojos,
        owner_puzzle_hash,
        store_launcher_id: Bytes32::default(),
        root_hash: Bytes32::default(),
        epoch: BigInt::from(0),
        collateral_dig_base_units: 0,
    }
}

/// A [`MirrorSpends`] whose single spend CANNOT be signed, for testing the signer's failure path.
///
/// The puzzle reveal is a truncated CLVM cons, so computing the required signatures fails before any
/// key is consulted. That is the only way to reach `WalletSigner::sign`'s error arm without a chain:
/// an empty spend set always succeeds, and a well-formed one signs.
///
/// `#[cfg(test)]` for the same reason [`empty_for_tests`] is — the no-public-constructor property is
/// the whole authority bound. Owned by this signer's wallet, so the test that uses it is exercising
/// the SIGNING failure and not the ownership refusal in front of it.
#[cfg(test)]
pub(crate) fn unsignable_for_tests(owner_puzzle_hash: Bytes32) -> MirrorSpends {
    use chia_protocol::Program;

    MirrorSpends {
        operation: MirrorOperation::Create,
        spends: vec![CoinSpend::new(
            Coin::new(Bytes32::default(), Bytes32::default(), 1),
            Program::from(vec![0xff_u8]),
            Program::from(vec![0x80_u8]),
        )],
        fee_mojos: 0,
        owner_puzzle_hash,
        store_launcher_id: Bytes32::default(),
        root_hash: Bytes32::default(),
        epoch: BigInt::from(0),
        collateral_dig_base_units: 0,
    }
}
