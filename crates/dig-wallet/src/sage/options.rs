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
//! ## `exercise_options` — a documented follow-on, not implemented here
//!
//! Exercising an option additionally requires reconstructing the UNDERLYING coin's OWN
//! lineage (it sits at a derived puzzle hash the wallet's ordinary HD puzzle-hash
//! subscription set does not cover — see design B.3) and building the `MipsSpend`/merkle-proof
//! machinery `OptionUnderlying::exercise_spend` needs. That is a substantial unit on its own;
//! [`exercise_options_unimplemented`] documents the exact reason and is the seam the
//! follow-on lands in. `get_options`/`get_option`/`mint_option`/`transfer_options` are fully
//! served in the meantime.

use chia::puzzles::Memos;
use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_wallet_sdk::driver::{
    OptionContract, OptionInfo, OptionLauncher, OptionLauncherInfo, OptionType, Puzzle,
    SpendContext, StandardLayer,
};
use chia_wallet_sdk::types::Conditions;

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

/// `exercise_options` — a documented follow-on (module docs), not a silent gap: returns a
/// clear, typed `500` error naming the exact missing piece (underlying-coin lineage tracking
/// and the `MipsSpend`/merkle-proof exercise machinery) rather than mis-building or panicking.
/// `sage::rpc`'s `exercise_options` dispatch returns this directly.
pub fn exercise_options_unimplemented() -> Error {
    Error::internal(
        "exercise_options is not yet implemented: it requires tracking the option's \
         underlying-lock coin lineage (a derived, non-HD puzzle hash outside the wallet's \
         ordinary subscription set) plus the MipsSpend/merkle-proof exercise machinery — see \
         SPEC.md §18 and crate::sage::options module docs",
    )
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

    fn signer_for(sk: chia::bls::SecretKey) -> WalletSigner {
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
        use chia::traits::Streamable;
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

    #[test]
    fn exercise_options_returns_a_clear_named_error() {
        let e = exercise_options_unimplemented();
        assert_eq!(e.kind, super::super::ErrorKind::Internal);
        assert!(e.message.contains("not yet implemented"));
    }
}
