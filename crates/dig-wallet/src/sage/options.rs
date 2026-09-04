//! The option-contract suite (design A.5 "Transactions" option methods, #205 PR4):
//! `get_options`/`get_option` (DB reads), `mint_option`/`transfer_options` (real
//! `chia-wallet-sdk` `OptionLauncher`/`OptionContract` builders — never hand-rolled CLVM,
//! SYSTEM.md §4.1), following the exact builder pattern [`super::mint`] established for
//! DID/NFT mint + transfer.
//!
//! ## Scope: XCH-underlying options (documented, not a gap)
//!
//! Chia's option-contract puzzle (`chia-sdk-driver`'s `OptionLauncher`/`OptionUnderlying`)
//! locks an UNDERLYING asset at a puzzle hash the option computes, and separately tags a
//! STRIKE asset type the exerciser must pay. The strike side is a pure enum tag with no
//! extra coin-construction work at mint time (whoever exercises later funds it) — so
//! [`build_mint_option`] accepts XCH **or** CAT strikes for free. The UNDERLYING side is
//! different: locking it requires actually constructing a coin of that asset kind at the
//! option's `p2_puzzle_hash`, which for a CAT means a full CAT-send (lineage resolution +
//! `Cat::spend_all`, i.e. the whole `send_cat` machinery) redirected to a derived
//! destination, and for an NFT means a full transfer. This module scopes the underlying to
//! **XCH** (mint an option that locks plain XCH, common/simple case: "N mojos, redeemable
//! for the strike within `expiration_seconds`") — CAT/NFT-underlying options are a tracked
//! follow-on once that machinery is factored for reuse across `send_cat`/`transfer_nfts`.
//!
//! ## `exercise_options` - served, bounded, and built through `dig-options`
//!
//! Exercise is NOT re-derived here. It is built through **`dig-options`**, the ecosystem's
//! canonical option-contract crate (`modules/crates/00-foundation/dig-options`), for two
//! reasons a local re-implementation would have had to rediscover:
//!
//! 1. `dig_options::exercise` emits the **underlying-claim leg**. Unlocking the underlying puts
//!    it on a BARE settlement coin anyone can spend; the claim leg is what pays it to the
//!    holder, and consensus does not force it. Omitting it strands the underlying for any
//!    mempool watcher to take while the holder has already paid the strike.
//! 2. `dig_options::rehydrate` VERIFIES a reconstructed `OptionUnderlying` against three
//!    independent on-chain commitments, so a wrong creator puzzle hash is REJECTED rather than
//!    silently building a spend against a different merkle root.
//!
//! ### The served envelope, and what returns a 400
//!
//! Exercise needs the whole underlying `Coin` and the creator puzzle hash. Neither is
//! invertible from the option puzzle: the underlying sits behind a 1-of-2 merkle path, and its
//! coin sits at a derived puzzle hash the wallet does not subscribe to, so the replica holds no
//! row for it. Both are therefore recovered from what this wallet recorded AT MINT
//! (`underlying_parent_coin_id`, plus creator = the minting address), and every recovered value
//! is verified by `rehydrate` before it is used.
//!
//! The served envelope is an **XCH-underlying, XCH-strike option this wallet minted** and still
//! owns, whose mint recorded the underlying parent. Anything outside it -- an option acquired by
//! TRANSFER (reconstruction would need replaying the mint launcher spend from chain history), a
//! CAT/NFT strike, or a row predating the `underlying_parent_coin_id` column -- returns a
//! **400 naming the limitation**, never a 500 and never a mis-built spend. That mirrors the
//! guard idiom [`build_mint_option`] already uses.

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::Memos;
use chia_wallet_sdk::driver::{
    OptionContract, OptionInfo, OptionLauncher, OptionLauncherInfo, OptionType, OptionUnderlying,
    Puzzle, SpendContext, StandardLayer,
};
use chia_wallet_sdk::types::Conditions;
use clvm_utils::ToTreeHash;
use dig_options::{Owner, RehydratedTerms, StrikePayment};

use super::db::OptionDbRow;
use super::singleton::{self, ParentSpend};
use super::spend::{self, WalletSigner};
use super::types::{Amount, Asset, AssetKind, OptionAsset, OptionRecord};
use super::{Error, Result};

/// The p2 (owner) [`StandardLayer`] for a coin at `puzzle_hash`.
fn p2_for(signer: &WalletSigner, puzzle_hash: Bytes32) -> Result<StandardLayer> {
    let pk = signer
        .synthetic_for(puzzle_hash)
        .ok_or_else(|| Error::internal("no signing key for the coin's puzzle hash"))?;
    Ok(StandardLayer::new(pk))
}

/// Build a Sage [`OptionType`] strike descriptor from the wire [`OptionAsset`] (`None` id =
/// XCH). CAT-strike is fully supported (it is a pure tag; the exerciser funds it later).
pub fn strike_type_from_asset(asset: &OptionAsset) -> Result<OptionType> {
    let amount = asset
        .amount
        .to_u64()
        .ok_or_else(|| Error::api("strike amount exceeds u64 range"))?;
    match &asset.asset_id {
        None => Ok(OptionType::Xch { amount }),
        Some(id) => Ok(OptionType::Cat {
            asset_id: singleton::bytes32_from_hex(id)?,
            amount,
        }),
    }
}

/// Build the (unsigned) coin spends that mint an XCH-underlying option contract (module
/// docs: scope). `underlying_inputs` fund the locked underlying amount (change back to
/// `change`); `launcher_inputs` fund the 1-mojo launcher + `fee` (change back to `change`).
/// `owner_ph` is both the option's eventual p2 owner AND the creator (clawback beneficiary)
/// puzzle hash — the minting wallet's own address, matching Sage's single-wallet model.
/// Returns the built spends and the minted option's [`OptionInfo`] (from which the caller
/// derives the full [`OptionRecord`]).
#[allow(clippy::too_many_arguments)]
pub fn build_mint_option(
    signer: &WalletSigner,
    underlying_inputs: &[Coin],
    underlying_amount: u64,
    launcher_inputs: &[Coin],
    strike: OptionType,
    expiration_seconds: u64,
    owner_ph: Bytes32,
    change: Bytes32,
    fee: u64,
) -> Result<(Vec<CoinSpend>, OptionInfo)> {
    let underlying_first = *underlying_inputs
        .first()
        .ok_or_else(|| Error::api("no underlying funding coins"))?;
    let underlying_total: u64 = underlying_inputs.iter().map(|c| c.amount).sum();
    if underlying_total < underlying_amount {
        return Err(Error::api(format!(
            "insufficient funds for the underlying lock: have {underlying_total}, need {underlying_amount}"
        )));
    }
    let launcher_first = *launcher_inputs
        .first()
        .ok_or_else(|| Error::api("no launcher funding coins"))?;
    let launcher_total: u64 = launcher_inputs.iter().map(|c| c.amount).sum();
    let launcher_need = 1u64
        .checked_add(fee)
        .ok_or_else(|| Error::api("fee overflow"))?;
    if launcher_total < launcher_need {
        return Err(Error::api(format!(
            "insufficient funds for the option launcher: have {launcher_total}, need {launcher_need} (1 mojo + fee)"
        )));
    }

    let mut ctx = SpendContext::new();
    let info = OptionLauncherInfo::new(
        owner_ph,
        owner_ph,
        expiration_seconds,
        underlying_amount,
        strike,
    );
    let launcher = OptionLauncher::new(&mut ctx, launcher_first.coin_id(), info, 1)
        .map_err(|e| Error::internal(format!("build option launcher: {e:?}")))?;
    let p2_option = launcher.p2_puzzle_hash();

    // Lock the underlying XCH at p2_option.
    let underlying_p2 = p2_for(signer, underlying_first.puzzle_hash)?;
    let mut underlying_conditions =
        Conditions::new().create_coin(p2_option, underlying_amount, Memos::None);
    let underlying_change = underlying_total - underlying_amount;
    if underlying_change > 0 {
        underlying_conditions =
            underlying_conditions.create_coin(change, underlying_change, Memos::None);
    }
    underlying_p2
        .spend(&mut ctx, underlying_first, underlying_conditions)
        .map_err(|e| Error::internal(format!("lock underlying: {e:?}")))?;
    spend::link_rest(&mut ctx, signer, underlying_inputs)?;

    let underlying_coin = Coin::new(underlying_first.coin_id(), p2_option, underlying_amount);
    let launcher = launcher.with_underlying(underlying_coin.coin_id());
    let option_info = launcher.info();
    let (mint_conditions, _eve_option) = launcher
        .mint(&mut ctx)
        .map_err(|e| Error::internal(format!("mint option: {e:?}")))?;

    // Fund the 1-mojo launcher + fee.
    let launcher_p2 = p2_for(signer, launcher_first.puzzle_hash)?;
    let mut conditions = mint_conditions.assert_concurrent_spend(underlying_first.coin_id());
    let launcher_change = launcher_total - 1 - fee;
    if launcher_change > 0 {
        conditions = conditions.create_coin(change, launcher_change, Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }
    launcher_p2
        .spend(&mut ctx, launcher_first, conditions)
        .map_err(|e| Error::internal(format!("fund option launcher: {e:?}")))?;
    spend::link_rest(&mut ctx, signer, launcher_inputs)?;

    Ok((ctx.take(), option_info))
}

/// Parse the spendable [`OptionContract`] for `child` from its `parent` spend INTO `ctx` (the
/// option twin of [`super::singleton::parse_nft_in`]/[`super::singleton::parse_did_in`]).
/// `None` if the parent is not an option contract or the child does not match.
pub fn parse_option_in(
    ctx: &mut SpendContext,
    parent: &ParentSpend,
    child: Coin,
) -> Result<Option<OptionContract>> {
    let puzzle_ptr = ctx
        .alloc(&Program::from(parent.puzzle_reveal.clone()))
        .map_err(|e| Error::internal(format!("alloc parent puzzle: {e}")))?;
    let parent_puzzle = Puzzle::parse(ctx, puzzle_ptr);
    let solution_ptr = ctx
        .alloc(&Program::from(parent.solution.clone()))
        .map_err(|e| Error::internal(format!("alloc parent solution: {e}")))?;
    match OptionContract::parse_child(ctx, parent.coin, parent_puzzle, solution_ptr) {
        Ok(Some(opt)) if opt.coin.coin_id() == child.coin_id() => Ok(Some(opt)),
        _ => Ok(None),
    }
}

/// Build the (unsigned) coin spends that transfer each option in `options` (parent spend +
/// current coin) to `dest`, optionally paying `fee` from `fee_coins` (XCH).
pub fn build_option_transfer(
    signer: &WalletSigner,
    options: &[(ParentSpend, Coin)],
    dest: Bytes32,
    fee_coins: &[Coin],
    change: Bytes32,
    fee: u64,
) -> Result<Vec<CoinSpend>> {
    if options.is_empty() {
        return Err(Error::api("no options to transfer"));
    }
    let mut ctx = SpendContext::new();
    let mut first_singleton: Option<Bytes32> = None;
    for (parent, child) in options {
        let option: OptionContract =
            parse_option_in(&mut ctx, parent, *child)?.ok_or_else(|| {
                Error::not_found("coin is not a spendable option (or parent not found)")
            })?;
        let p2 = p2_for(signer, option.info.p2_puzzle_hash)?;
        if first_singleton.is_none() {
            first_singleton = Some(option.coin.coin_id());
        }
        let _child = option
            .transfer(&mut ctx, &p2, dest, Conditions::new())
            .map_err(|e| Error::internal(format!("transfer option: {e:?}")))?;
    }
    reserve_fee_linked(&mut ctx, signer, fee_coins, change, fee, first_singleton)?;
    Ok(ctx.take())
}

/// Reserve `fee` from `fee_coins`, change to `change`, linked to `link_to` via
/// `assert_concurrent_spend` (mirrors [`super::mint`]'s private helper — kept local since
/// this module's fee coin is XCH-only, same shape).
fn reserve_fee_linked(
    ctx: &mut SpendContext,
    signer: &WalletSigner,
    fee_coins: &[Coin],
    change: Bytes32,
    fee: u64,
    link_to: Option<Bytes32>,
) -> Result<()> {
    if fee == 0 {
        return Ok(());
    }
    let first = *fee_coins
        .first()
        .ok_or_else(|| Error::api("a non-zero fee requires XCH fee coins"))?;
    let total: u64 = fee_coins.iter().map(|c| c.amount).sum();
    if total < fee {
        return Err(Error::api(format!(
            "insufficient XCH for the fee: have {total}, need {fee}"
        )));
    }
    let mut conditions = Conditions::new().reserve_fee(fee);
    if let Some(coin_id) = link_to {
        conditions = conditions.assert_concurrent_spend(coin_id);
    }
    let change_amount = total - fee;
    if change_amount > 0 {
        conditions = conditions.create_coin(change, change_amount, Memos::None);
    }
    spend::spend_std(ctx, signer, first, conditions)?;
    spend::link_rest(ctx, signer, fee_coins)?;
    Ok(())
}

/// The terms an option's exercise needs that its puzzle does NOT reveal, recovered from what
/// this wallet recorded at mint and returned only when ALL of them are present.
///
/// `Ok(None)` means "this wallet cannot reconstruct this option" -- the caller turns that into a
/// 400 naming the limitation. It is never a reason to substitute a default: `creator_puzzle_hash`
/// is committed only inside the underlying's clawback path, so a wrong value produces a spend
/// against a different merkle root and burns a real fee for nothing.
///
/// # Why `p2_puzzle_hash` is a legitimate creator candidate
///
/// [`build_mint_option`] passes `owner_ph` as BOTH the option's p2 owner and the creator, so for
/// an option this wallet minted and still holds the two are equal. That makes the row's current
/// owner a *candidate*, not an assumption: `dig_options::rehydrate` rejects it against the
/// on-chain 1-of-2 path if the option was in fact created by someone else.
pub fn underlying_from_row(row: &OptionDbRow) -> Result<Option<(Coin, RehydratedTerms)>> {
    let Some(parent_hex) = row.underlying_parent_coin_id.as_deref() else {
        return Ok(None);
    };
    let Some(record) = record_from_row(row, "") else {
        return Ok(None);
    };
    let strike = strike_type_from_asset(&OptionAsset {
        asset_id: record.strike_asset.asset_id.clone(),
        amount: record.strike_amount.clone(),
    })?;
    let underlying_amount = record
        .underlying_amount
        .to_u64()
        .ok_or_else(|| Error::api("stored underlying amount exceeds u64 range"))?;
    let launcher_id = parse_hash(&row.option_id)?;
    let creator_puzzle_hash = parse_hash(&row.p2_puzzle_hash)?;
    let terms = RehydratedTerms {
        creator_puzzle_hash,
        expiry_seconds: record.expiration_seconds,
        strike_type: strike,
    };
    // Rebuild the underlying coin. Its puzzle hash is the underlying's own 1-of-2 path hash,
    // which is computed from the SAME terms -- so `rehydrate`'s path-hash check is tautological
    // under this construction and is NOT what makes this sound. The check that carries it is the
    // coin-id check against `option.info.underlying_coin_id`, an independent value the option
    // singleton itself commits to: a wrong creator hash or expiry changes the path hash, hence
    // the coin id, and is rejected there.
    let underlying = OptionUnderlying::new(
        launcher_id,
        creator_puzzle_hash,
        record.expiration_seconds,
        underlying_amount,
        strike,
    );
    let coin = Coin::new(
        parse_hash(parent_hex)?,
        underlying.tree_hash().into(),
        underlying_amount,
    );
    Ok(Some((coin, terms)))
}

/// The option's current owner (p2) puzzle hash, parsed from its stored row.
pub fn p2_hash_of(row: &OptionDbRow) -> Result<Bytes32> {
    parse_hash(&row.p2_puzzle_hash)
}

/// Build the (unsigned) spends that reserve `fee` from `fee_coins` alone, linked to `link_to`.
///
/// Kept separate from [`build_exercise_option`] because `dig_options::exercise` drains the whole
/// [`SpendContext`] it is handed; the fee leg is built in its own context and appended.
pub fn build_fee_only(
    signer: &WalletSigner,
    fee_coins: &[Coin],
    change: Bytes32,
    fee: u64,
    link_to: Option<Bytes32>,
) -> Result<Vec<CoinSpend>> {
    let mut ctx = SpendContext::new();
    reserve_fee_linked(&mut ctx, signer, fee_coins, change, fee, link_to)?;
    Ok(ctx.take())
}

/// Parse a 32-byte hex hash (with or without a `0x` prefix).
fn parse_hash(hex_str: &str) -> Result<Bytes32> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|_| Error::api("expected a hex-encoded 32-byte hash"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::api("expected a hex-encoded 32-byte hash"))?;
    Ok(Bytes32::from(arr))
}

/// Build the (unsigned) coin spends that EXERCISE `option` -- paying the strike from
/// `strike_funding` and unlocking the underlying to the option's current owner.
///
/// Delegates to `dig_options::exercise`, which emits BOTH settlement legs (the strike to the
/// creator and the unlocked underlying to the holder) in one bundle. The returned spends MUST be
/// broadcast intact: dropping the underlying-claim leg leaves the unlocked underlying on a
/// publicly-claimable settlement coin.
///
/// `strike_funding` MUST sit at the option's own p2 puzzle hash. One [`Owner`] authorizes both
/// the singleton spend and the strike-funding spend, so a funding coin at a different address
/// would be signed for the wrong key; requiring them equal is a guard, not a limitation the
/// caller cannot satisfy (the option's p2 hash is an ordinary wallet address).
pub fn build_exercise_option(
    signer: &WalletSigner,
    option: &(ParentSpend, Coin),
    underlying_coin: Coin,
    terms: &RehydratedTerms,
    strike_funding: Coin,
) -> Result<Vec<CoinSpend>> {
    let mut ctx = SpendContext::new();
    let (parent, child) = option;
    let contract = parse_option_in(&mut ctx, parent, *child)?
        .ok_or_else(|| Error::not_found("coin is not a spendable option (or parent not found)"))?;

    if !matches!(terms.strike_type, OptionType::Xch { .. }) {
        return Err(Error::api(
            "exercise_options: only an XCH strike can be exercised (see crate::sage::options \
             module docs); the CAT/NFT settlement leg is not built by dig-options",
        ));
    }
    if strike_funding.puzzle_hash != contract.info.p2_puzzle_hash {
        return Err(Error::api(
            "exercise_options: the strike must be funded from a coin at the option's own owner \
             address",
        ));
    }

    // Every reconstructed field is verified here against the option's on-chain commitments; a
    // mismatch means this wallet did not mint the option (or its record drifted), which is a
    // documented 400 rather than an internal error.
    let created = dig_options::rehydrate(&contract, terms, underlying_coin).map_err(|e| {
        Error::api(format!(
            "exercise_options: this wallet cannot reconstruct the option's underlying terms \
             ({e}); only an option minted by this wallet, still owned by it, and recorded with \
             its underlying parent can be exercised"
        ))
    })?;

    let pk = signer
        .synthetic_for(contract.info.p2_puzzle_hash)
        .ok_or_else(|| Error::api("no signing key for the option's owner address"))?;
    let holder = Owner::Standard(pk);
    let spend = dig_options::exercise(
        &mut ctx,
        &holder,
        &created,
        &StrikePayment {
            funding_coin: strike_funding,
        },
    )
    .map_err(|e| Error::internal(format!("exercise option: {e}")))?;
    Ok(spend.coin_spends)
}

/// Render a stored [`OptionDbRow`] + its parsed strike/underlying fields as the wire
/// [`OptionRecord`]. Used by `get_options`/`get_option` in `sage::rpc`.
pub fn record_from_row(row: &OptionDbRow, address: &str) -> Option<OptionRecord> {
    serde_json::from_str(&row.record_json)
        .ok()
        .map(|mut r: OptionRecord| {
            // The stored record is authored at mint/sync time; keep the DB's own
            // visible/coin/address/created_height columns authoritative on read.
            r.visible = row.visible;
            r.coin_id = row.coin_id.clone();
            r.address = address.to_string();
            r.created_height = row.created_height.map(|h| h as u32);
            r
        })
}

/// A minimal [`Asset`] descriptor for `asset_id` (`None` = XCH; `Some` = a CAT with only the
/// asset id known — matching `sage::rpc`'s `coin_asset` helper for an unattributed CAT).
pub fn asset_for(asset_id: Option<&str>) -> Asset {
    match asset_id {
        None => Asset {
            asset_id: None,
            name: Some("Chia".into()),
            ticker: Some("XCH".into()),
            precision: 12,
            icon_url: None,
            description: None,
            is_sensitive_content: false,
            is_visible: true,
            revocation_address: None,
            kind: AssetKind::Token,
        },
        Some(id) => Asset {
            asset_id: Some(id.to_string()),
            name: None,
            ticker: None,
            precision: 3,
            icon_url: None,
            description: None,
            is_sensitive_content: false,
            is_visible: true,
            revocation_address: None,
            kind: AssetKind::Token,
        },
    }
}

/// Build the initial [`OptionRecord`] for a freshly-minted option (used to seed the stored
/// `record_json` — later reads patch the mutable fields via [`record_from_row`]).
#[allow(clippy::too_many_arguments)]
pub fn new_record(
    launcher_id: &str,
    coin_id: &str,
    address: &str,
    amount: u64,
    underlying_asset: Asset,
    underlying_amount: u64,
    underlying_coin_id: &str,
    strike_asset: Asset,
    strike_amount: u64,
    expiration_seconds: u64,
) -> OptionRecord {
    OptionRecord {
        launcher_id: launcher_id.to_string(),
        visible: true,
        coin_id: coin_id.to_string(),
        address: address.to_string(),
        amount: Amount::u64(amount),
        underlying_asset,
        underlying_amount: Amount::u64(underlying_amount),
        underlying_coin_id: underlying_coin_id.to_string(),
        strike_asset,
        strike_amount: Amount::u64(strike_amount),
        expiration_seconds,
        name: None,
        created_height: None,
        created_timestamp: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_sdk_test::{BlsPair, Simulator};
    use chia_wallet_sdk::types::TESTNET11_CONSTANTS;

    fn signer_for(sk: chia_bls::SecretKey) -> WalletSigner {
        WalletSigner::new(vec![sk], TESTNET11_CONSTANTS.agg_sig_me_additional_data)
    }

    /// Mint an XCH-underlying, XCH-strike option end-to-end on the simulator: build,
    /// validate via `dig-clvm`, sign, and broadcast.
    #[test]
    fn mint_xch_option_builds_validates_and_broadcasts_on_simulator() {
        let mut sim = Simulator::new();
        let alice = sim.bls(2_000);
        let signer = signer_for(alice.sk.clone());

        let underlying_coin = sim.new_coin(alice.puzzle_hash, 1_000);
        let launcher_coin = sim.new_coin(alice.puzzle_hash, 10);

        let (coin_spends, info) = build_mint_option(
            &signer,
            &[underlying_coin],
            1_000,
            &[launcher_coin],
            OptionType::Xch { amount: 500 },
            3600,
            alice.puzzle_hash,
            alice.puzzle_hash,
            0,
        )
        .unwrap();
        assert_ne!(info.launcher_id, Bytes32::default());
        spend::run_and_validate(&coin_spends).unwrap();
        let sig = signer.sign(&coin_spends).unwrap();
        sim.new_transaction(chia_protocol::SpendBundle::new(coin_spends, sig))
            .expect("simulator must accept the option mint");
    }

    #[test]
    fn mint_option_rejects_insufficient_underlying_funds() {
        let pair = BlsPair::new(11);
        let signer = signer_for(pair.sk.clone());
        let ph = *signer.puzzle_hashes().iter().next().unwrap();
        let underlying = Coin::new(Bytes32::new([1; 32]), ph, 10);
        let launcher = Coin::new(Bytes32::new([2; 32]), ph, 10);
        let err = build_mint_option(
            &signer,
            &[underlying],
            1_000, // more than the 10-mojo underlying coin covers
            &[launcher],
            OptionType::Xch { amount: 1 },
            60,
            ph,
            ph,
            0,
        )
        .unwrap_err();
        assert!(err.message.contains("underlying"));
    }

    /// End-to-end: mint an option (via the SDK driver directly, mirroring the crate's own
    /// test fixture), extract its eve parent spend, then build+validate+broadcast a
    /// transfer via [`build_option_transfer`].
    #[test]
    fn transfer_option_builds_validates_and_broadcasts_on_simulator() {
        use chia_traits::Streamable;
        use chia_wallet_sdk::driver::SpendContext as Ctx;

        let mut sim = Simulator::new();
        let alice = sim.bls(2);
        let signer = signer_for(alice.sk.clone());
        let alice_p2 = StandardLayer::new(alice.pk);

        let ctx = &mut Ctx::new();
        let parent_coin = sim.new_coin(alice.puzzle_hash, 1);
        let launcher = OptionLauncher::new(
            ctx,
            alice.coin.coin_id(),
            OptionLauncherInfo::new(
                alice.puzzle_hash,
                alice.puzzle_hash,
                10,
                1,
                OptionType::Xch { amount: 1 },
            ),
            1,
        )
        .unwrap();
        let p2_option = launcher.p2_puzzle_hash();
        alice_p2
            .spend(
                ctx,
                parent_coin,
                Conditions::new().create_coin(p2_option, 1, Memos::None),
            )
            .unwrap();
        let underlying_coin = Coin::new(parent_coin.coin_id(), p2_option, 1);
        let launcher = launcher.with_underlying(underlying_coin.coin_id());
        let (mint_option, option) = launcher.mint(ctx).unwrap();
        alice_p2.spend(ctx, alice.coin, mint_option).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();

        // The minted option's parent is the eve option (spent in the mint bundle).
        let eve_id = option.coin.parent_coin_info;
        let eve_coin = sim.coin_state(eve_id).unwrap().coin;
        let puzzle = sim.puzzle_reveal(eve_id).unwrap();
        let solution = sim.solution(eve_id).unwrap();
        let parent = ParentSpend {
            coin: eve_coin,
            puzzle_reveal: puzzle.to_bytes().unwrap(),
            solution: solution.to_bytes().unwrap(),
        };

        let dest = Bytes32::new([7; 32]);
        let coin_spends = build_option_transfer(
            &signer,
            &[(parent, option.coin)],
            dest,
            &[],
            alice.puzzle_hash,
            0,
        )
        .unwrap();
        spend::run_and_validate(&coin_spends).unwrap();
        let sig = signer.sign(&coin_spends).unwrap();
        sim.new_transaction(chia_protocol::SpendBundle::new(coin_spends, sig))
            .expect("simulator must accept the option transfer");
    }

    #[test]
    fn strike_type_from_asset_maps_xch_and_cat() {
        let xch = OptionAsset {
            asset_id: None,
            amount: Amount::u64(5),
        };
        assert!(matches!(
            strike_type_from_asset(&xch).unwrap(),
            OptionType::Xch { amount: 5 }
        ));
        let cat = OptionAsset {
            asset_id: Some("aa".repeat(32)),
            amount: Amount::u64(9),
        };
        assert!(matches!(
            strike_type_from_asset(&cat).unwrap(),
            OptionType::Cat { amount: 9, .. }
        ));
    }

    #[test]
    fn new_record_and_record_from_row_round_trip() {
        let rec = new_record(
            "opt1",
            "coin1",
            "xch1a",
            1,
            asset_for(None),
            1000,
            "u1",
            asset_for(None),
            500,
            3600,
        );
        assert_eq!(rec.launcher_id, "opt1");
        let json = serde_json::to_string(&rec).unwrap();
        let row = OptionDbRow {
            option_id: "opt1".into(),
            coin_id: "coin2".into(), // simulate a later coin after a spend
            underlying_coin_id: "u1".into(),
            underlying_parent_coin_id: None,
            underlying_delegated_puzzle_hash: "dph".into(),
            p2_puzzle_hash: "p2".into(),
            visible: false,
            created_height: Some(42),
            record_json: json,
        };
        let restored = record_from_row(&row, "xch1b").unwrap();
        assert_eq!(restored.coin_id, "coin2");
        assert_eq!(restored.address, "xch1b");
        assert!(!restored.visible);
        assert_eq!(restored.created_height, Some(42));
        assert_eq!(restored.underlying_amount.to_u64(), Some(1000));
        assert_eq!(restored.underlying_asset.ticker.as_deref(), Some("XCH"));
    }

    /// Exercise an option end to end on the simulator.
    ///
    /// This REPLACES `exercise_options_returns_a_clear_named_error`, which asserted only that a
    /// named error existed. That assertion passes under the defect -- it measures the string
    /// table, not the method -- so it is deleted rather than kept alongside.
    ///
    /// Asserts three things the simulator can actually see: the bundle is accepted, the option
    /// singleton is MELTED (its coin is spent and it creates no successor), and a coin of the
    /// full underlying amount lands at the holder's own puzzle hash. The third is the one that
    /// catches a dropped underlying-claim leg: without it the underlying is stranded on a
    /// publicly-claimable settlement coin and the holder receives nothing.
    #[test]
    fn exercise_option_spend_is_accepted_by_the_simulator() {
        use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
        use chia_traits::Streamable;
        use chia_wallet_sdk::driver::SpendContext as Ctx;

        const UNDERLYING: u64 = 1_000;
        const STRIKE: u64 = 500;
        // An ABSOLUTE unix timestamp far in the future: exercise emits an
        // assert-before-seconds-absolute, so an expiry in the past is refused by consensus and
        // would make this test measure the wrong refusal.
        const EXPIRY: u64 = 4_000_000_000;

        let mut sim = Simulator::new();
        let alice = sim.bls(1);
        let signer = signer_for(alice.sk.clone());
        let alice_p2 = StandardLayer::new(alice.pk);

        let ctx = &mut Ctx::new();
        let underlying_funding = sim.new_coin(alice.puzzle_hash, UNDERLYING);
        let strike_funding = sim.new_coin(alice.puzzle_hash, STRIKE);

        let launcher = OptionLauncher::new(
            ctx,
            alice.coin.coin_id(),
            OptionLauncherInfo::new(
                alice.puzzle_hash,
                alice.puzzle_hash,
                EXPIRY,
                UNDERLYING,
                OptionType::Xch { amount: STRIKE },
            ),
            1,
        )
        .unwrap();
        let p2_option = launcher.p2_puzzle_hash();
        alice_p2
            .spend(
                ctx,
                underlying_funding,
                Conditions::new().create_coin(p2_option, UNDERLYING, Memos::None),
            )
            .unwrap();
        let underlying_coin = Coin::new(underlying_funding.coin_id(), p2_option, UNDERLYING);
        let launcher = launcher.with_underlying(underlying_coin.coin_id());
        let (mint_option, option) = launcher.mint(ctx).unwrap();
        alice_p2.spend(ctx, alice.coin, mint_option).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();

        // The current option's parent is the eve option, spent in the mint bundle.
        let eve_id = option.coin.parent_coin_info;
        let parent = ParentSpend {
            coin: sim.coin_state(eve_id).unwrap().coin,
            puzzle_reveal: sim.puzzle_reveal(eve_id).unwrap().to_bytes().unwrap(),
            solution: sim.solution(eve_id).unwrap().to_bytes().unwrap(),
        };

        let terms = RehydratedTerms {
            creator_puzzle_hash: alice.puzzle_hash,
            expiry_seconds: EXPIRY,
            strike_type: OptionType::Xch { amount: STRIKE },
        };
        let coin_spends = build_exercise_option(
            &signer,
            &(parent, option.coin),
            underlying_coin,
            &terms,
            strike_funding,
        )
        .expect("the exercise must build");

        let sig = signer.sign(&coin_spends).unwrap();
        sim.new_transaction(chia_protocol::SpendBundle::new(coin_spends, sig))
            .expect("the simulator must accept the option exercise");

        // (b) the option singleton is melted -- spent, with no successor.
        let melted = sim.coin_state(option.coin.coin_id()).unwrap();
        assert!(
            melted.spent_height.is_some(),
            "the option singleton must be spent by its exercise"
        );

        // (c) the unlocked underlying reached the holder. The claim leg spends the settlement
        // coin the underlying lands on and pays the holder's own p2 hash; naming that coin is
        // what makes a dropped claim leg visible rather than merely unasserted.
        let settlement = Coin::new(
            underlying_coin.coin_id(),
            SETTLEMENT_PAYMENT_HASH.into(),
            UNDERLYING,
        );
        let holder_coin = Coin::new(settlement.coin_id(), alice.puzzle_hash, UNDERLYING);
        assert!(
            sim.coin_state(holder_coin.coin_id()).is_some(),
            "the exercised underlying must land at the holder's address, not stay on the \
             publicly-claimable settlement coin"
        );
    }

    /// An oversized strike-funding coin must have its excess RETURNED, not burned (#550).
    ///
    /// Every other exercise test in this module funds the strike with EXACTLY the strike amount,
    /// which is the one case where the defect this test exists to catch is invisible. Through
    /// `dig-options` 0.4.1 the builder spent the whole funding coin and emitted only the
    /// settlement output, so the difference left the spend as an implicit network fee. It was
    /// never a deliberate fee: `sage::rpc::exercise_options` picks the SMALLEST spendable coin at
    /// the owner address that covers the strike, and the smallest coin that covers a 0.1 XCH
    /// strike is routinely 5 XCH, so the loss was silent, unbounded, and reached real funds.
    ///
    /// The assertion is value conservation rather than the mere presence of a change coin,
    /// because those fail differently. `additions` containing `(owner, excess)` proves change was
    /// built; `fee == 0` proves nothing ALSO leaked out some other leg. A future change that
    /// returns the excess and burns an equal amount elsewhere would pass the first and fail the
    /// second.
    #[test]
    fn an_oversized_strike_funding_coin_returns_its_excess_instead_of_burning_it() {
        use chia_traits::Streamable;
        use chia_wallet_sdk::driver::SpendContext as Ctx;

        const UNDERLYING: u64 = 1_000;
        const STRIKE: u64 = 500;
        // The whole point of the test: the funding coin is LARGER than the strike.
        const EXCESS: u64 = 4_500;
        const FUNDING: u64 = STRIKE + EXCESS;
        const EXPIRY: u64 = 4_000_000_000;
        // The option singleton's own amount, burned by the melt (see the doc comment).
        const SINGLETON_AMOUNT: u64 = 1;

        let mut sim = Simulator::new();
        let alice = sim.bls(1);
        let signer = signer_for(alice.sk.clone());
        let alice_p2 = StandardLayer::new(alice.pk);

        let ctx = &mut Ctx::new();
        let underlying_funding = sim.new_coin(alice.puzzle_hash, UNDERLYING);
        let strike_funding = sim.new_coin(alice.puzzle_hash, FUNDING);

        let launcher = OptionLauncher::new(
            ctx,
            alice.coin.coin_id(),
            OptionLauncherInfo::new(
                alice.puzzle_hash,
                alice.puzzle_hash,
                EXPIRY,
                UNDERLYING,
                OptionType::Xch { amount: STRIKE },
            ),
            1,
        )
        .unwrap();
        let p2_option = launcher.p2_puzzle_hash();
        alice_p2
            .spend(
                ctx,
                underlying_funding,
                Conditions::new().create_coin(p2_option, UNDERLYING, Memos::None),
            )
            .unwrap();
        let underlying_coin = Coin::new(underlying_funding.coin_id(), p2_option, UNDERLYING);
        let launcher = launcher.with_underlying(underlying_coin.coin_id());
        let (mint_option, option) = launcher.mint(ctx).unwrap();
        alice_p2.spend(ctx, alice.coin, mint_option).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();

        let eve_id = option.coin.parent_coin_info;
        let parent = ParentSpend {
            coin: sim.coin_state(eve_id).unwrap().coin,
            puzzle_reveal: sim.puzzle_reveal(eve_id).unwrap().to_bytes().unwrap(),
            solution: sim.solution(eve_id).unwrap().to_bytes().unwrap(),
        };

        let terms = RehydratedTerms {
            creator_puzzle_hash: alice.puzzle_hash,
            expiry_seconds: EXPIRY,
            strike_type: OptionType::Xch { amount: STRIKE },
        };
        let coin_spends = build_exercise_option(
            &signer,
            &(parent, option.coin),
            underlying_coin,
            &terms,
            strike_funding,
        )
        .expect("the exercise must build");

        // Run the spends through `dig-clvm` to read what they actually create. `SpendResult::fee`
        // IS the burn: the amount consumed that no output claims.
        let result = spend::run_and_validate(&coin_spends).expect("the exercise must validate");

        assert!(
            result
                .additions
                .iter()
                .any(|c| c.puzzle_hash == alice.puzzle_hash && c.amount == EXCESS),
            "the {EXCESS} mojos above the strike must come back as a coin at the funding \
             coin's OWN puzzle hash; additions were {:?}",
            result
                .additions
                .iter()
                .map(|c| (c.puzzle_hash, c.amount))
                .collect::<Vec<_>>()
        );

        assert_eq!(
            result.fee, SINGLETON_AMOUNT,
            "the ONLY mojo this bundle may burn is the melted option singleton's own. \
             Anything above that is the strike-funding coin's excess being burned -- on \
             dig-options 0.4.1 this read {} ({SINGLETON_AMOUNT} + {EXCESS} over a \
             {STRIKE} strike)",
            SINGLETON_AMOUNT + EXCESS
        );

        // And it must still be a spend the network accepts -- returning change is worthless if it
        // breaks the exercise.
        let sig = signer.sign(&coin_spends).unwrap();
        sim.new_transaction(chia_protocol::SpendBundle::new(coin_spends, sig))
            .expect("the simulator must accept an exercise that returns strike change");
    }

    /// A row with no recorded underlying parent is UNKNOWN, and unknown must refuse rather than
    /// default. A default here would build a spend against a different coin.
    #[test]
    fn an_option_without_a_recorded_underlying_parent_is_not_reconstructible() {
        let row = OptionDbRow {
            option_id: "11".repeat(32),
            coin_id: "c1".into(),
            underlying_coin_id: "u1".into(),
            underlying_parent_coin_id: None,
            underlying_delegated_puzzle_hash: "dph".into(),
            p2_puzzle_hash: "22".repeat(32),
            visible: true,
            created_height: None,
            record_json: serde_json::to_string(&new_record(
                &"11".repeat(32),
                &"11".repeat(32),
                "xch1a",
                1,
                asset_for(None),
                1_000,
                "u1",
                asset_for(None),
                500,
                4_000_000_000,
            ))
            .unwrap(),
        };
        assert!(underlying_from_row(&row).unwrap().is_none());
    }
}
