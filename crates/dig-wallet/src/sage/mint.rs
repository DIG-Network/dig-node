//! DID/NFT mint + transfer spend builders (design A.5, #218): `create_did`,
//! `bulk_mint_nfts`, `transfer_nfts`, `transfer_dids`.
//!
//! Every spend is built with the canonical `chia-wallet-sdk` driver constructors
//! ([`Launcher::create_simple_did`], [`IntermediateLauncher`] + [`NftMint`],
//! [`Nft::transfer`]/[`Did::transfer`]) — never hand-rolled CLVM (SYSTEM.md §4.1),
//! following the proven `digstore-chain` builder pattern. Coins come from the wallet DB;
//! the assembled bundle is validated by `dig-clvm` and signed by the node-custodied
//! [`WalletSigner`] in the RPC layer ([`super::rpc`]) — exactly like the #216 send/spend
//! group. Nothing here signs or broadcasts.
//!
//! ## Mint funding model (Chia is bundle-wide, not per-coin, conservation)
//!
//! `bulk_mint_nfts` launches one [`IntermediateLauncher`] per NFT OFF the DID coin and
//! spends the DID once (`did.update`) emitting every mint's conditions — so all NFTs are
//! minted atomically AND attributed to the creator DID in one bundle (the collection-mint
//! pattern). Each NFT singleton costs 1 mojo; the DID coin only recreates itself, so an
//! XCH **funding coin** supplies the launcher mojos + the fee (change returns to the
//! wallet). Because Chia enforces conservation over the whole bundle, the launcher value
//! flows from the funding coin through the aggregate.

use chia::puzzles::nft::NftMetadata;
use chia::puzzles::Memos;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_wallet_sdk::driver::{
    Did, IntermediateLauncher, Launcher, Nft, NftMint as SdkNftMint, SingletonInfo, SpendContext,
    StandardLayer,
};
use chia_wallet_sdk::types::conditions::TransferNft;
use chia_wallet_sdk::types::Conditions;

use super::singleton::{self, ParentSpend};
use super::spend::{self, WalletSigner};
use super::{Error, Result};

/// The p2 (owner) [`StandardLayer`] for a coin/singleton at `puzzle_hash`, or a locked
/// error when the wallet holds no key for it.
fn p2_for(signer: &WalletSigner, puzzle_hash: Bytes32) -> Result<StandardLayer> {
    let pk = signer
        .synthetic_for(puzzle_hash)
        .ok_or_else(|| Error::internal("no signing key for the coin/singleton puzzle hash"))?;
    Ok(StandardLayer::new(pk))
}

// ---- create_did -----------------------------------------------------------

/// Build the (unsigned) coin spends that create a simple DID funded from `inputs` (XCH
/// coins the wallet controls), returning the spends and the DID's launcher id. The DID
/// singleton takes 1 mojo; `fee` is reserved and change returns to `change`.
///
/// A "simple" DID has no recovery list and `num_verifications_required = 1` (the common
/// case Sage creates). The DID's on-chain display name is a wallet label, not an on-chain
/// field, so `name` is stored by the caller, not here.
pub fn build_create_did(
    signer: &WalletSigner,
    inputs: &[Coin],
    change: Bytes32,
    fee: u64,
) -> Result<(Vec<CoinSpend>, Bytes32)> {
    let first = *inputs.first().ok_or_else(|| Error::api("no input coins"))?;
    let total: u64 = inputs.iter().map(|c| c.amount).sum();
    let need = 1u64
        .checked_add(fee)
        .ok_or_else(|| Error::api("fee overflow"))?;
    if total < need {
        return Err(Error::api(format!(
            "insufficient funds: have {total}, need {need} (1 mojo singleton + fee)"
        )));
    }

    let mut ctx = SpendContext::new();
    let p2 = p2_for(signer, first.puzzle_hash)?;
    let (create_conditions, did) = Launcher::new(first.coin_id(), 1)
        .create_simple_did(&mut ctx, &p2)
        .map_err(|e| Error::internal(format!("create simple did: {e:?}")))?;

    let mut conditions = create_conditions;
    let change_amount = total - 1 - fee;
    if change_amount > 0 {
        conditions = conditions.create_coin(change, change_amount, Memos::None);
    }
    if fee > 0 {
        conditions = conditions.reserve_fee(fee);
    }
    spend::spend_std(&mut ctx, signer, first, conditions)?;
    spend::link_rest(&mut ctx, signer, inputs)?;

    Ok((ctx.take(), did.info.launcher_id))
}

// ---- bulk_mint_nfts -------------------------------------------------------

/// A resolved NFT-mint plan: the serialized on-chain metadata + owner/royalty config for
/// one NFT, ready to build the SDK [`NftMint`] from.
pub struct NftMintPlan {
    /// The on-chain NFT metadata (URIs + hashes + edition).
    pub metadata: NftMetadata,
    /// The p2 (owner) puzzle hash the minted NFT is created for.
    pub owner_ph: Bytes32,
    /// The royalty payout puzzle hash.
    pub royalty_ph: Bytes32,
    /// The royalty share in ten-thousandths (300 = 3%).
    pub royalty_basis_points: u16,
}

/// Build the (unsigned) coin spends that bulk-mint `plans.len()` NFTs attributed to `did`,
/// funded from `funding` (XCH coins), returning the spends and the minted NFT launcher ids.
///
/// One [`IntermediateLauncher`] per NFT is launched off the DID coin and the DID is spent
/// once emitting all mint conditions (so every NFT is DID-attributed atomically). `funding`
/// supplies the per-NFT launcher mojos + `fee`; change returns to `change`.
pub fn build_bulk_mint(
    signer: &WalletSigner,
    did: Did,
    plans: &[NftMintPlan],
    funding: &[Coin],
    change: Bytes32,
    fee: u64,
) -> Result<(Vec<CoinSpend>, Vec<Bytes32>)> {
    if plans.is_empty() {
        return Err(Error::api("bulk_mint_nfts requires at least one mint"));
    }
    let first_funding = *funding.first().ok_or_else(|| {
        Error::api("bulk_mint_nfts requires an XCH funding coin for the NFT launchers + fee")
    })?;
    let funding_total: u64 = funding.iter().map(|c| c.amount).sum();
    let n = plans.len() as u64;
    let need = n
        .checked_add(fee)
        .ok_or_else(|| Error::api("mint funding overflow"))?;
    if funding_total < need {
        return Err(Error::api(format!(
            "insufficient XCH to mint: have {funding_total}, need {need} (1 mojo/NFT + fee)"
        )));
    }

    let mut ctx = SpendContext::new();
    let did_p2 = p2_for(signer, did.info.p2_puzzle_hash)?;
    let did_launcher = did.info.launcher_id;
    let did_inner_ph: Bytes32 = did.info.inner_puzzle_hash().into();
    let did_coin_id = did.coin.coin_id();

    let total = plans.len();
    let mut all_mint_conditions = Conditions::new();
    let mut launcher_ids = Vec::with_capacity(total);
    for (i, plan) in plans.iter().enumerate() {
        let metadata_ptr = ctx
            .alloc_hashed(&plan.metadata)
            .map_err(|e| Error::internal(format!("alloc nft metadata {i}: {e:?}")))?;
        let transfer = TransferNft::new(Some(did_launcher), Vec::new(), Some(did_inner_ph));
        let mut nft_mint = SdkNftMint::new(
            metadata_ptr,
            plan.owner_ph,
            plan.royalty_basis_points,
            Some(transfer),
        );
        nft_mint.royalty_puzzle_hash = plan.royalty_ph;

        let (mint_conditions, nft) = IntermediateLauncher::new(did_coin_id, i, total)
            .create(&mut ctx)
            .map_err(|e| Error::internal(format!("create intermediate launcher {i}: {e:?}")))?
            .mint_nft(&mut ctx, &nft_mint)
            .map_err(|e| Error::internal(format!("mint nft {i}: {e:?}")))?;
        all_mint_conditions = all_mint_conditions.extend(mint_conditions);
        launcher_ids.push(nft.info.launcher_id);
    }

    // Spend the DID once, acknowledging every attribution (emits all mint conditions). The
    // recreated DID is not needed here (a subsequent mint re-fetches it from chain).
    let _recreated = did
        .update(&mut ctx, &did_p2, all_mint_conditions)
        .map_err(|e| Error::internal(format!("spend did for bulk mint: {e:?}")))?;

    // The funding coin supplies the launcher mojos + fee (change back to the wallet), and
    // is bound to the DID spend so it cannot be spent without the mint.
    let mut fund_conditions = Conditions::new().assert_concurrent_spend(did_coin_id);
    let change_amount = funding_total - n - fee;
    if change_amount > 0 {
        fund_conditions = fund_conditions.create_coin(change, change_amount, Memos::None);
    }
    if fee > 0 {
        fund_conditions = fund_conditions.reserve_fee(fee);
    }
    spend::spend_std(&mut ctx, signer, first_funding, fund_conditions)?;
    spend::link_rest(&mut ctx, signer, funding)?;

    Ok((ctx.take(), launcher_ids))
}

// ---- transfer_nfts / transfer_dids ----------------------------------------

/// Build the (unsigned) coin spends that transfer each NFT in `nfts` (each given as its
/// parent spend and current coin) to `dest`, optionally paying `fee` from `fee_coins`
/// (XCH), returning the spends. Each NFT is re-parsed from its parent spend in this build's
/// own context (its metadata pointer is allocator-relative) then re-targeted to `dest`.
pub fn build_nft_transfer(
    signer: &WalletSigner,
    nfts: &[(ParentSpend, Coin)],
    dest: Bytes32,
    fee_coins: &[Coin],
    change: Bytes32,
    fee: u64,
) -> Result<Vec<CoinSpend>> {
    if nfts.is_empty() {
        return Err(Error::api("no NFTs to transfer"));
    }
    let mut ctx = SpendContext::new();
    let mut first_singleton: Option<Bytes32> = None;
    for (parent, child) in nfts {
        let nft: Nft = singleton::parse_nft_in(&mut ctx, parent, *child)?
            .ok_or_else(|| Error::not_found("coin is not a spendable NFT (or parent not found)"))?;
        let p2 = p2_for(signer, nft.info.p2_puzzle_hash)?;
        if first_singleton.is_none() {
            first_singleton = Some(nft.coin.coin_id());
        }
        let _child = nft
            .transfer(&mut ctx, &p2, dest, Conditions::new())
            .map_err(|e| Error::internal(format!("transfer nft: {e:?}")))?;
    }
    reserve_transfer_fee(&mut ctx, signer, fee_coins, change, fee, first_singleton)?;
    Ok(ctx.take())
}

/// Build the (unsigned) coin spends that transfer each DID in `dids` to `dest`, optionally
/// paying `fee` from `fee_coins` (XCH) — the DID twin of [`build_nft_transfer`].
pub fn build_did_transfer(
    signer: &WalletSigner,
    dids: &[(ParentSpend, Coin)],
    dest: Bytes32,
    fee_coins: &[Coin],
    change: Bytes32,
    fee: u64,
) -> Result<Vec<CoinSpend>> {
    if dids.is_empty() {
        return Err(Error::api("no DIDs to transfer"));
    }
    let mut ctx = SpendContext::new();
    let mut first_singleton: Option<Bytes32> = None;
    for (parent, child) in dids {
        let did: Did = singleton::parse_did_in(&mut ctx, parent, *child)?
            .ok_or_else(|| Error::not_found("coin is not a spendable DID (or parent not found)"))?;
        let p2 = p2_for(signer, did.info.p2_puzzle_hash)?;
        if first_singleton.is_none() {
            first_singleton = Some(did.coin.coin_id());
        }
        let _child = did
            .transfer(&mut ctx, &p2, dest, Conditions::new())
            .map_err(|e| Error::internal(format!("transfer did: {e:?}")))?;
    }
    reserve_transfer_fee(&mut ctx, signer, fee_coins, change, fee, first_singleton)?;
    Ok(ctx.take())
}

/// Reserve `fee` from `fee_coins` (change back to `change`), binding the fee coin to the
/// first transferred singleton via `assert_concurrent_spend` so the two settle atomically.
/// A no-op when `fee == 0`.
fn reserve_transfer_fee(
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

/// Build an [`NftMetadata`] from wire fields (hashes hex-decoded).
#[allow(clippy::too_many_arguments)]
pub fn nft_metadata(
    data_uris: Vec<String>,
    data_hash: Option<&str>,
    metadata_uris: Vec<String>,
    metadata_hash: Option<&str>,
    license_uris: Vec<String>,
    license_hash: Option<&str>,
    edition_number: Option<u32>,
    edition_total: Option<u32>,
) -> Result<NftMetadata> {
    let hash = |h: Option<&str>| -> Result<Option<Bytes32>> {
        match h {
            Some(s) => Ok(Some(singleton::bytes32_from_hex(s)?)),
            None => Ok(None),
        }
    };
    Ok(NftMetadata {
        edition_number: edition_number.unwrap_or(1) as u64,
        edition_total: edition_total.unwrap_or(1) as u64,
        data_uris,
        data_hash: hash(data_hash)?,
        metadata_uris,
        metadata_hash: hash(metadata_hash)?,
        license_uris,
        license_hash: hash(license_hash)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_sdk_test::{BlsPair, Simulator};
    use chia_wallet_sdk::driver::SpendContext as Ctx;
    use chia_wallet_sdk::types::TESTNET11_CONSTANTS;

    fn signer_for(sk: chia::bls::SecretKey) -> WalletSigner {
        WalletSigner::new(vec![sk], TESTNET11_CONSTANTS.agg_sig_me_additional_data)
    }

    #[test]
    fn create_did_builds_validates_and_broadcasts_on_simulator() {
        let mut sim = Simulator::new();
        let alice = sim.bls(2);
        let signer = signer_for(alice.sk.clone());

        let (coin_spends, launcher_id) =
            build_create_did(&signer, &[alice.coin], alice.puzzle_hash, 1).unwrap();
        assert_ne!(launcher_id, Bytes32::default());
        spend::run_and_validate(&coin_spends).unwrap();
        let sig = signer.sign(&coin_spends).unwrap();
        sim.new_transaction(chia_protocol::SpendBundle::new(coin_spends, sig))
            .expect("simulator must accept the DID creation");
    }

    #[test]
    fn create_did_rejects_insufficient_funds() {
        let pair = BlsPair::new(9);
        let signer = signer_for(pair.sk.clone());
        let ph = *signer.puzzle_hashes().iter().next().unwrap();
        let coin = Coin::new(Bytes32::new([1; 32]), ph, 0);
        assert!(build_create_did(&signer, &[coin], ph, 5).is_err());
    }

    /// Mint 2 NFTs attributed to a freshly-created DID off one funding coin, validate via
    /// dig-clvm, and broadcast to the simulator (which verifies signatures on L1).
    #[test]
    fn bulk_mint_two_nfts_attributed_to_did_on_simulator() {
        let mut sim = Simulator::new();
        let alice = sim.bls(10);
        let signer = signer_for(alice.sk.clone());
        let alice_p2 = StandardLayer::new(alice.pk);

        // Create the DID directly so we hold the spendable `Did` (same ctx as the mint).
        let ctx = &mut Ctx::new();
        let (create_did, did) = Launcher::new(alice.coin.coin_id(), 1)
            .create_simple_did(ctx, &alice_p2)
            .unwrap();
        alice_p2.spend(ctx, alice.coin, create_did).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();

        // A funding coin for the two launcher mojos + fee.
        let funding = sim.new_coin(alice.puzzle_hash, 10);
        let plans = vec![
            NftMintPlan {
                metadata: NftMetadata {
                    data_uris: vec!["https://example.com/0.png".into()],
                    ..Default::default()
                },
                owner_ph: alice.puzzle_hash,
                royalty_ph: alice.puzzle_hash,
                royalty_basis_points: 300,
            },
            NftMintPlan {
                metadata: NftMetadata {
                    data_uris: vec!["https://example.com/1.png".into()],
                    ..Default::default()
                },
                owner_ph: alice.puzzle_hash,
                royalty_ph: alice.puzzle_hash,
                royalty_basis_points: 500,
            },
        ];
        let (coin_spends, launcher_ids) =
            build_bulk_mint(&signer, did, &plans, &[funding], alice.puzzle_hash, 0).unwrap();
        assert_eq!(launcher_ids.len(), 2);
        assert_ne!(launcher_ids[0], launcher_ids[1]);
        spend::run_and_validate(&coin_spends).unwrap();
        let sig = signer.sign(&coin_spends).unwrap();
        sim.new_transaction(chia_protocol::SpendBundle::new(coin_spends, sig))
            .expect("simulator must accept the bulk mint");
    }

    /// End-to-end: mint an NFT (via the SDK), extract its parent spend from the simulator,
    /// then build+validate+broadcast a transfer to a second address.
    #[test]
    fn transfer_nft_builds_validates_and_broadcasts_on_simulator() {
        use chia::traits::Streamable;
        let mut sim = Simulator::new();
        let alice = sim.bls(2);
        let signer = signer_for(alice.sk.clone());
        let alice_p2 = StandardLayer::new(alice.pk);

        // Mint an NFT owned by alice.
        let ctx = &mut Ctx::new();
        let metadata = ctx.alloc_hashed(&NftMetadata::default()).unwrap();
        let (mint_conditions, nft) = IntermediateLauncher::new(alice.coin.coin_id(), 0, 1)
            .create(ctx)
            .unwrap()
            .mint_nft(ctx, &SdkNftMint::new(metadata, alice.puzzle_hash, 0, None))
            .unwrap();
        alice_p2.spend(ctx, alice.coin, mint_conditions).unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();

        // The minted NFT's parent is the eve NFT (spent in the mint bundle). Rebuild that
        // eve spend as a ParentSpend so the transfer builder can re-parse the NFT.
        let eve_id = nft.coin.parent_coin_info;
        let eve_coin = sim.coin_state(eve_id).unwrap().coin;
        let puzzle = sim.puzzle_reveal(eve_id).unwrap();
        let solution = sim.solution(eve_id).unwrap();
        let parent = ParentSpend {
            coin: eve_coin,
            puzzle_reveal: puzzle.to_bytes().unwrap(),
            solution: solution.to_bytes().unwrap(),
        };
        let child = nft.coin;

        let dest = Bytes32::new([7; 32]);
        let coin_spends =
            build_nft_transfer(&signer, &[(parent, child)], dest, &[], alice.puzzle_hash, 0)
                .unwrap();
        spend::run_and_validate(&coin_spends).unwrap();
        let sig = signer.sign(&coin_spends).unwrap();
        sim.new_transaction(chia_protocol::SpendBundle::new(coin_spends, sig))
            .expect("simulator must accept the NFT transfer");
    }
}
