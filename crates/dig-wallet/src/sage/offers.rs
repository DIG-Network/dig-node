//! The offer suite (design A.5, #218): `make_offer`, `take_offer`, `view_offer`,
//! `combine_offers`, `cancel_offer` spend/parse builders (`get_offers`/`get_offer` are pure
//! DB reads in [`super::rpc`]).
//!
//! Offers are built with the canonical `chia-wallet-sdk` action system (`Spends`/`Action`/
//! `RequestedPayments`/`Offer`) — never hand-rolled CLVM (SYSTEM.md §4.1) — mirroring the
//! proven `digstore-chain` offer builder exactly, but signed by the node-custodied
//! [`WalletSigner`] over coins resolved from the wallet DB (the #216 pattern). Maker/taker
//! coins are supplied already-resolved ([`OfferInputs`]) so the builders are pure and
//! simulator-testable; the RPC layer resolves them from the DB + CAT lineage. Nothing here
//! broadcasts — the assembled bundle is validated by `dig-clvm` and pushed under the
//! [`super::spend::Broadcaster`] gate in the RPC layer (mock/simulator only in CI).

use chia::puzzles::offer::{NotarizedPayment, Payment};
use chia::puzzles::Memos;
use chia_protocol::{Bytes32, Coin, SpendBundle};
use chia_wallet_sdk::driver::{
    decode_offer, encode_offer, Action, AssetInfo, Cat, CatAssetInfo, Id, Offer, Relation,
    RequestedPayments, SpendContext, Spends, StandardLayer,
};
use chia_wallet_sdk::types::puzzles::SettlementPayment;
use chia_wallet_sdk::types::{Conditions, Mod};

use super::spend::WalletSigner;
use super::types::{Amount, Asset, AssetKind, NftRoyalty, OfferAsset, OfferSummary};
use super::{Error, Result};

/// The offer settlement puzzle hash (`SETTLEMENT_PAYMENT_HASH`), from the `SettlementPayment`
/// mod hash (no direct dependency on the puzzle-constants crate).
fn settlement_payment_hash() -> Bytes32 {
    Bytes32::from(<[u8; 32]>::from(SettlementPayment::mod_hash()))
}

/// One asset leg of an offer: XCH (`asset_id == None`) or a CAT by TAIL hash, with its
/// amount in the asset's smallest unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferLeg {
    /// The CAT asset id / TAIL hash, or `None` for XCH.
    pub asset_id: Option<Bytes32>,
    /// The amount in the asset's smallest unit.
    pub amount: u64,
}

/// The maker's (or taker's) funding coins for one side of an offer: spendable XCH coins and
/// resolved CAT coins (with lineage proofs), all at the wallet's puzzle hashes.
#[derive(Default)]
pub struct OfferInputs {
    /// Spendable XCH coins.
    pub xch: Vec<Coin>,
    /// Resolved CAT coins (carry their own asset id + lineage proof).
    pub cats: Vec<Cat>,
}

/// A deterministic, dependency-free offer id: the tree hash of the sorted offered coin ids
/// (the same value `Offer::nonce` derives), hex-encoded. Stable for the same offered set,
/// so `get_offer`/`cancel_offer` can look an offer up by it.
pub fn offer_id_from_coin_ids(offered_coin_ids: Vec<Bytes32>) -> String {
    hex::encode(Offer::nonce(offered_coin_ids))
}

/// The offer id of a decoded offer (from its offered coins).
pub fn offer_id_of(offer: &Offer) -> String {
    offer_id_from_coin_ids(
        offer
            .offered_coins()
            .flatten()
            .iter()
            .map(|c| c.coin_id())
            .collect(),
    )
}

/// The offer id of a bech32m `offer1…` string (decodes it, then derives the id).
pub fn offer_id_of_str(offer_str: &str) -> Result<String> {
    let mut ctx = SpendContext::new();
    Ok(offer_id_of(&decode_offer_in(&mut ctx, offer_str)?))
}

/// Decode a bech32m `offer1…` string into a spendable [`Offer`] in `ctx` (its parsed NFT
/// metadata pointers are allocator-relative, so a take MUST reuse the same `ctx`).
pub fn decode_offer_in(ctx: &mut SpendContext, offer_str: &str) -> Result<Offer> {
    let trimmed = offer_str.trim();
    if !trimmed.starts_with("offer1") {
        return Err(Error::api(
            "not a Chia offer: expected a bech32m string starting with 'offer1'",
        ));
    }
    let bundle = decode_offer(trimmed).map_err(|e| Error::api(format!("invalid offer: {e:?}")))?;
    Offer::from_spend_bundle(ctx, &bundle)
        .map_err(|e| Error::api(format!("could not parse offer: {e:?}")))
}

/// Build AND sign a make-offer: OFFER `offered` (funded from `inputs`) and REQUEST
/// `requested` (paid to `receive_ph`), reserving `fee`; change/surplus returns to
/// `change_ph`. Returns the bech32m `offer1…` string + its offer id.
#[allow(clippy::too_many_arguments)]
pub fn build_make_offer(
    signer: &WalletSigner,
    inputs: &OfferInputs,
    offered: &[OfferLeg],
    requested: &[OfferLeg],
    receive_ph: Bytes32,
    change_ph: Bytes32,
    fee: u64,
) -> Result<(String, String)> {
    if offered.is_empty() {
        return Err(Error::api("make_offer must offer at least one asset"));
    }
    if requested.is_empty() {
        return Err(Error::api("make_offer must request at least one asset"));
    }

    let settlement_ph = settlement_payment_hash();
    let mut ctx = SpendContext::new();
    let receive_hint = ctx
        .hint(receive_ph)
        .map_err(|e| Error::internal(format!("alloc receive hint: {e:?}")))?;

    let mut spends = Spends::new(change_ph);
    let mut offered_coin_ids: Vec<Bytes32> = Vec::new();
    let mut actions: Vec<Action> = Vec::new();

    for leg in offered {
        if leg.amount == 0 {
            return Err(Error::api("offered asset amount must be greater than zero"));
        }
        match leg.asset_id {
            None => {
                let chosen = select_xch(&inputs.xch, leg.amount.saturating_add(fee))?;
                for coin in &chosen {
                    spends.add(*coin);
                    offered_coin_ids.push(coin.coin_id());
                }
                actions.push(Action::send(
                    Id::Xch,
                    settlement_ph,
                    leg.amount,
                    Memos::None,
                ));
            }
            Some(asset_id) => {
                let chosen = select_cats(&inputs.cats, asset_id, leg.amount)?;
                for cat in &chosen {
                    spends.add(*cat);
                    offered_coin_ids.push(cat.coin.coin_id());
                }
                actions.push(Action::send(
                    Id::Existing(asset_id),
                    settlement_ph,
                    leg.amount,
                    Memos::None,
                ));
            }
        }
    }
    if offered_coin_ids.is_empty() {
        return Err(Error::api("make_offer selected no offered coins"));
    }

    let nonce = Offer::nonce(offered_coin_ids.clone());
    let mut requested_payments = RequestedPayments::new();
    let mut requested_asset_info = AssetInfo::new();
    for leg in requested {
        if leg.amount == 0 {
            return Err(Error::api(
                "requested asset amount must be greater than zero",
            ));
        }
        match leg.asset_id {
            None => requested_payments.xch.push(NotarizedPayment::new(
                nonce,
                vec![Payment::new(receive_ph, leg.amount, receive_hint)],
            )),
            Some(asset_id) => {
                requested_payments.cats.insert(
                    asset_id,
                    vec![NotarizedPayment::new(
                        nonce,
                        vec![Payment::new(receive_ph, leg.amount, receive_hint)],
                    )],
                );
                requested_asset_info
                    .insert_cat(asset_id, CatAssetInfo::new(None))
                    .map_err(|e| Error::internal(format!("insert requested cat info: {e:?}")))?;
            }
        }
    }

    if fee > 0 {
        actions.push(Action::fee(fee));
    }

    let deltas = spends
        .apply(&mut ctx, &actions)
        .map_err(|e| Error::internal(format!("apply make-offer actions: {e:?}")))?;
    spends.conditions.required = spends.conditions.required.extend(
        requested_payments
            .assertions(&mut ctx, &requested_asset_info)
            .map_err(|e| Error::internal(format!("requested payment assertions: {e:?}")))?,
    );
    spends
        .finish_with_keys(
            &mut ctx,
            &deltas,
            Relation::AssertConcurrent,
            &signer.key_map(),
        )
        .map_err(|e| Error::internal(format!("finish make-offer spends: {e:?}")))?;

    let coin_spends = ctx.take();
    let signature = signer.sign(&coin_spends)?;
    let offer = Offer::from_input_spend_bundle(
        &mut ctx,
        SpendBundle::new(coin_spends, signature),
        requested_payments,
        requested_asset_info,
    )
    .map_err(|e| Error::internal(format!("assemble make-offer: {e:?}")))?;
    let bundle = offer
        .to_spend_bundle(&mut ctx)
        .map_err(|e| Error::internal(format!("serialize offer: {e:?}")))?;
    let offer_str =
        encode_offer(&bundle).map_err(|e| Error::internal(format!("encode offer: {e:?}")))?;
    Ok((offer_str, offer_id_from_coin_ids(offered_coin_ids)))
}

/// Build AND sign the taker side of `offer_str`, funding the maker's requested payments from
/// `inputs`, and return the combined (maker + taker) [`SpendBundle`], ready to broadcast.
/// Change/received assets route to `change_ph`; `fee` is an optional XCH network fee.
pub fn build_take_offer(
    signer: &WalletSigner,
    offer_str: &str,
    inputs: &OfferInputs,
    change_ph: Bytes32,
    fee: u64,
) -> Result<SpendBundle> {
    let mut ctx = SpendContext::new();
    let offer = decode_offer_in(&mut ctx, offer_str)?;

    let mut spends = Spends::new(change_ph);
    spends.add(offer.offered_coins().clone());
    for coin in &inputs.xch {
        spends.add(*coin);
    }
    for cat in &inputs.cats {
        spends.add(*cat);
    }

    let mut actions = offer.requested_payments().actions();
    if fee > 0 {
        actions.push(Action::fee(fee));
    }

    let deltas = spends
        .apply(&mut ctx, &actions)
        .map_err(|e| Error::internal(format!("apply take-offer actions: {e:?}")))?;
    spends
        .finish_with_keys(
            &mut ctx,
            &deltas,
            Relation::AssertConcurrent,
            &signer.key_map(),
        )
        .map_err(|e| Error::internal(format!("finish take-offer spends: {e:?}")))?;

    let taker_coin_spends = ctx.take();
    let taker_sig = signer.sign(&taker_coin_spends)?;
    Ok(offer.take(SpendBundle::new(taker_coin_spends, taker_sig)))
}

/// Combine several `offer1…` strings into one offer (their coin spends + aggregated
/// signatures), returning the combined bech32m string. Byte-level aggregation of the decoded
/// spend bundles (Sage's `combine_offers`).
pub fn combine_offers(offers: &[String]) -> Result<String> {
    if offers.len() < 2 {
        return Err(Error::api("combine_offers requires at least two offers"));
    }
    let mut coin_spends = Vec::new();
    let mut signature = chia::bls::Signature::default();
    for s in offers {
        let trimmed = s.trim();
        if !trimmed.starts_with("offer1") {
            return Err(Error::api(
                "not a Chia offer: expected a bech32m 'offer1' string",
            ));
        }
        let bundle =
            decode_offer(trimmed).map_err(|e| Error::api(format!("invalid offer: {e:?}")))?;
        coin_spends.extend(bundle.coin_spends);
        signature += &bundle.aggregated_signature;
    }
    encode_offer(&SpendBundle::new(coin_spends, signature))
        .map_err(|e| Error::internal(format!("encode combined offer: {e:?}")))
}

/// Build AND sign the cancel spends for an offer the wallet MADE: reclaim its offered
/// (settlement-bound) coins back to `change_ph`, reserving `fee`. Returns the unsigned coin
/// spends (the RPC layer validates + signs + broadcasts under its gate).
pub fn build_cancel_offer(
    signer: &WalletSigner,
    offer_str: &str,
    change_ph: Bytes32,
    fee: u64,
) -> Result<Vec<chia_protocol::CoinSpend>> {
    let mut ctx = SpendContext::new();
    let offer = decode_offer_in(&mut ctx, offer_str)?;
    let cancellable = offer
        .cancellable_coin_spends()
        .map_err(|e| Error::internal(format!("compute cancellable coin spends: {e:?}")))?;
    if cancellable.is_empty() {
        return Err(Error::not_found(
            "no cancellable coins in this offer (already settled or not the maker's)",
        ));
    }

    let mut ctx = SpendContext::new();
    let mut first = true;
    for cs in &cancellable {
        let pk = signer.synthetic_for(cs.coin.puzzle_hash).ok_or_else(|| {
            Error::internal("no signing key for an offered coin (not this wallet's offer?)")
        })?;
        let p2 = StandardLayer::new(pk);
        let mut conditions = Conditions::new().create_coin(change_ph, cs.coin.amount, Memos::None);
        if first && fee > 0 {
            conditions = conditions.reserve_fee(fee);
            first = false;
        }
        p2.spend(&mut ctx, cs.coin, conditions)
            .map_err(|e| Error::internal(format!("build cancel spend: {e:?}")))?;
    }
    Ok(ctx.take())
}

/// Summarize an offer without taking it: the maker's offered assets and the assets the taker
/// must pay (`view_offer`). Only fungible (XCH/CAT) legs + NFT royalties are surfaced.
pub fn summarize_offer(offer_str: &str) -> Result<OfferSummary> {
    let mut ctx = SpendContext::new();
    let offer = decode_offer_in(&mut ctx, offer_str)?;

    let offered_amounts = offer.offered_coins().amounts();
    let mut maker: Vec<OfferAsset> = Vec::new();
    if offered_amounts.xch > 0 {
        maker.push(xch_offer_asset(offered_amounts.xch));
    }
    for (asset_id, amount) in &offered_amounts.cats {
        maker.push(cat_offer_asset(*asset_id, *amount));
    }
    // Offered NFT royalties (royalty carried by an NFT the maker offers).
    for r in offer.offered_royalties() {
        if let Some(a) = maker.first_mut() {
            a.nft_royalty = Some(NftRoyalty {
                royalty_address: hex::encode(r.puzzle_hash),
                royalty_basis_points: r.basis_points,
            });
        }
    }

    let requested_amounts = offer.requested_payments().amounts();
    let mut taker: Vec<OfferAsset> = Vec::new();
    if requested_amounts.xch > 0 {
        taker.push(xch_offer_asset(requested_amounts.xch));
    }
    for (asset_id, amount) in &requested_amounts.cats {
        taker.push(cat_offer_asset(*asset_id, *amount));
    }

    Ok(OfferSummary {
        fee: Amount::u64(0),
        maker,
        taker,
        expiration_height: None,
        expiration_timestamp: None,
    })
}

fn xch_offer_asset(amount: u64) -> OfferAsset {
    OfferAsset {
        asset: Asset {
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
        amount: Amount::u64(amount),
        royalty: Amount::u64(0),
        nft_royalty: None,
        option_assets: None,
    }
}

fn cat_offer_asset(asset_id: Bytes32, amount: u64) -> OfferAsset {
    OfferAsset {
        asset: Asset {
            asset_id: Some(hex::encode(asset_id)),
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
        amount: Amount::u64(amount),
        royalty: Amount::u64(0),
        nft_royalty: None,
        option_assets: None,
    }
}

/// Greedily select XCH coins (largest first) covering `need`.
fn select_xch(coins: &[Coin], need: u64) -> Result<Vec<Coin>> {
    let mut sorted: Vec<Coin> = coins.to_vec();
    sorted.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.coin_id().cmp(&b.coin_id())));
    let mut sum = 0u64;
    let mut out = Vec::new();
    for c in sorted {
        if sum >= need {
            break;
        }
        sum += c.amount;
        out.push(c);
    }
    if sum < need {
        return Err(Error::api(format!(
            "insufficient XCH to offer: need {need} have {sum}"
        )));
    }
    Ok(out)
}

/// Greedily select CAT coins of `asset_id` (largest first) covering `need`.
fn select_cats(cats: &[Cat], asset_id: Bytes32, need: u64) -> Result<Vec<Cat>> {
    let mut sorted: Vec<Cat> = cats
        .iter()
        .filter(|c| c.info.asset_id == asset_id)
        .copied()
        .collect();
    sorted.sort_by(|a, b| {
        b.coin
            .amount
            .cmp(&a.coin.amount)
            .then(a.coin.coin_id().cmp(&b.coin.coin_id()))
    });
    let mut sum = 0u64;
    let mut out = Vec::new();
    for c in sorted {
        if sum >= need {
            break;
        }
        sum += c.coin.amount;
        out.push(c);
    }
    if sum < need {
        return Err(Error::api(format!(
            "insufficient CAT to offer: need {need} have {sum}"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_sdk_test::Simulator;
    use chia_wallet_sdk::types::TESTNET11_CONSTANTS;

    fn signer_for(sk: chia::bls::SecretKey) -> WalletSigner {
        WalletSigner::new(vec![sk], TESTNET11_CONSTANTS.agg_sig_me_additional_data)
    }

    #[test]
    fn make_offer_rejects_empty_sides() {
        let sim_sk = chia_sdk_test::BlsPair::new(1).sk;
        let signer = signer_for(sim_sk);
        let ph = *signer.puzzle_hashes().iter().next().unwrap();
        assert!(build_make_offer(
            &signer,
            &OfferInputs::default(),
            &[],
            &[OfferLeg {
                asset_id: None,
                amount: 1
            }],
            ph,
            ph,
            0
        )
        .is_err());
        assert!(build_make_offer(
            &signer,
            &OfferInputs::default(),
            &[OfferLeg {
                asset_id: None,
                amount: 1
            }],
            &[],
            ph,
            ph,
            0
        )
        .is_err());
    }

    #[test]
    fn combine_offers_requires_two() {
        assert!(combine_offers(&["offer1abc".into()]).is_err());
    }

    /// Two-party XCH↔XCH offer on the simulator: a maker offers XCH and requests XCH; a
    /// DISTINCT taker takes it; the combined bundle settles as one transaction and both
    /// sides' assets cross over. Proves make + take end-to-end, mainnet-safe (simulator).
    #[test]
    fn make_and_take_xch_for_xch_round_trip_on_simulator() {
        let mut sim = Simulator::new();
        let maker = sim.bls(1_000);
        let taker = sim.bls(1_000);
        let maker_signer = signer_for(maker.sk.clone());
        let taker_signer = signer_for(taker.sk.clone());

        // Maker OFFERS 300 XCH, REQUESTS 500 XCH paid to the maker.
        let (offer_str, offer_id) = build_make_offer(
            &maker_signer,
            &OfferInputs {
                xch: vec![maker.coin],
                cats: vec![],
            },
            &[OfferLeg {
                asset_id: None,
                amount: 300,
            }],
            &[OfferLeg {
                asset_id: None,
                amount: 500,
            }],
            maker.puzzle_hash,
            maker.puzzle_hash,
            0,
        )
        .unwrap();
        assert!(offer_str.starts_with("offer1"), "got {offer_str}");
        assert_eq!(offer_id.len(), 64, "offer id is 32-byte hex");

        // Inspect without taking: maker gives 300, taker pays 500.
        let summary = summarize_offer(&offer_str).unwrap();
        assert_eq!(summary.maker[0].amount.to_u64(), Some(300));
        assert_eq!(summary.taker[0].amount.to_u64(), Some(500));

        // Taker takes it, funding the 500 from its coin.
        let bundle = build_take_offer(
            &taker_signer,
            &offer_str,
            &OfferInputs {
                xch: vec![taker.coin],
                cats: vec![],
            },
            taker.puzzle_hash,
            0,
        )
        .unwrap();
        assert!(
            bundle.coin_spends.len() >= 2,
            "combined bundle has both maker + taker spends"
        );
        sim.new_transaction(bundle)
            .expect("simulator must accept the combined offer settlement");
    }

    #[test]
    fn cancel_reclaims_offered_coins_on_simulator() {
        let mut sim = Simulator::new();
        let maker = sim.bls(1_000);
        let signer = signer_for(maker.sk.clone());

        let (offer_str, _id) = build_make_offer(
            &signer,
            &OfferInputs {
                xch: vec![maker.coin],
                cats: vec![],
            },
            &[OfferLeg {
                asset_id: None,
                amount: 300,
            }],
            &[OfferLeg {
                asset_id: None,
                amount: 500,
            }],
            maker.puzzle_hash,
            maker.puzzle_hash,
            0,
        )
        .unwrap();

        let cancel_spends = build_cancel_offer(&signer, &offer_str, maker.puzzle_hash, 0).unwrap();
        assert!(!cancel_spends.is_empty());
        let sig = signer.sign(&cancel_spends).unwrap();
        sim.new_transaction(SpendBundle::new(cancel_spends, sig))
            .expect("simulator must accept the offer cancel (reclaim)");
    }
}
