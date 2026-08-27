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
//! ([`super::key::MirrorOperatingKey::sign`]) takes one and nothing else will type-check.
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
use chia_sdk_driver::Cat;
use dig_mirror_coin::{MirrorAdvertisement, MirrorCoin, MirrorError};
use num_bigint::BigInt;

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
}

/// Build the spends that lock `collateral_cat_mojos` of $DIG as a mirror for one `(store, root,
/// epoch)`.
///
/// A thin wrapper over `dig_mirror_coin::create`: it adds no conditions, alters no amount, and
/// changes no destination. Its whole contribution is that what comes back is a [`MirrorSpends`],
/// which is the thing the signer will accept.
///
/// `collateral_cat_mojos` is CAT mojos of $DIG — `dig_constants::MIRROR_COIN_COLLATERAL_CAT_MOJOS`,
/// which is 20 whole $DIG times `CAT_MOJOS_PER_DIG`. Passing the whole-$DIG figure would lock 0.02
/// $DIG and still look like a successful advertisement.
#[allow(clippy::too_many_arguments)]
pub fn build_create(
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: BigInt,
    urls: Vec<String>,
    collateral_cat_mojos: u64,
    dig_coins: Vec<Cat>,
    synthetic_key: PublicKey,
    fee_coins: Vec<Coin>,
    fee: u64,
) -> Result<MirrorSpends, MirrorError> {
    let spends = dig_mirror_coin::create(
        MirrorAdvertisement {
            store_launcher_id,
            root_hash,
            epoch,
            urls,
            collateral: collateral_cat_mojos,
        },
        dig_coins,
        synthetic_key,
        fee_coins,
        fee,
    )?;

    Ok(MirrorSpends {
        operation: MirrorOperation::Create,
        spends,
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
    })
}
