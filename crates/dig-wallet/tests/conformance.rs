//! Conformance harness (design **Part E**): assert the dig-node Sage-parity surface
//! matches the pinned Sage **v0.12.11** contract.
//!
//! Three checks:
//! 1. **Method-name parity** — every method the backend serves is a real Sage endpoint
//!    (a subset of the committed `endpoints.json` vector), so nothing is invented.
//! 2. **Byte-parity of the wire shapes** — representative responses serialize to the exact
//!    JSON `sage-api` emits (the `Amount` number/string threshold, snake_case, `null` for
//!    `None` in declaration order), and Sage-shaped requests deserialize losslessly.
//! 3. **Schema parity against the REAL generated OpenAPI** (design A.10) — `sage-cli` was
//!    built from the pinned `xch-dev/sage` `v0.12.11` tag and `sage rpc generate_openapi`
//!    run to produce `vectors/sage-openapi-v0.12.11.json` (committed here — no build step
//!    needed to re-derive it): every served method has a real `POST /{method}` path, and a
//!    set of representative response/request schemas are asserted field-name-identical to
//!    the real spec. This caught and fixed real drift during #205 PR4 (`OptionRecord` used
//!    `option_id` instead of the real `launcher_id`; `NetworkKind` was missing the real
//!    `unknown` variant; `save_user_theme`'s request wrongly carried a caller-supplied
//!    `theme` field the real Sage request does not have).

use dig_wallet::sage::rpc::WalletBackend;
use dig_wallet::sage::types::*;

/// The pinned Sage v0.12.11 endpoint catalogue (hand-authored from the design-doc research),
/// committed as the first conformance vector.
const SAGE_ENDPOINTS: &str = include_str!("vectors/sage-endpoints-v0.12.11.json");

/// The REAL OpenAPI spec generated from the pinned `xch-dev/sage` `v0.12.11` tag via
/// `cargo run --bin sage rpc generate_openapi` (design A.10) — the machine-checkable golden
/// vector `endpoints.json` approximates.
const SAGE_OPENAPI: &str = include_str!("vectors/sage-openapi-v0.12.11.json");

fn sage_openapi() -> serde_json::Value {
    serde_json::from_str(SAGE_OPENAPI).expect("the generated OpenAPI parses")
}

#[test]
fn every_supported_method_is_a_real_sage_endpoint() {
    let catalogue: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(SAGE_ENDPOINTS).expect("endpoints.json parses");
    for method in WalletBackend::SUPPORTED_METHODS {
        assert!(
            catalogue.contains_key(*method),
            "method `{method}` is not in the pinned Sage v0.12.11 endpoints.json — the \
             replica must not invent endpoints"
        );
    }
    // 25 core reads (#215) + 10 send/spend (#216) + 11 offer/mint/transfer (#218)
    // + 29 options/actions/themes/network (#205 PR4) = 75.
    assert_eq!(WalletBackend::SUPPORTED_METHODS.len(), 75);
}

#[test]
fn every_supported_method_has_a_real_path_in_the_generated_openapi() {
    let spec = sage_openapi();
    let paths = spec["paths"].as_object().expect("paths object");
    for method in WalletBackend::SUPPORTED_METHODS {
        let path = format!("/{method}");
        assert!(
            paths.contains_key(&path),
            "`{method}` has no `POST {path}` path in the generated Sage v0.12.11 OpenAPI"
        );
    }
    // The generated spec itself carries the full 100-endpoint surface (design A.5).
    assert_eq!(paths.len(), 100);
}

/// Assert `schema_name`'s real property set (from the generated OpenAPI) equals `fields`
/// exactly — the strongest available proof this replica's Rust type matches Sage byte-for-
/// byte at the field-name level.
fn assert_schema_fields(schema_name: &str, fields: &[&str]) {
    let spec = sage_openapi();
    let schema = &spec["components"]["schemas"][schema_name];
    let props = schema["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("{schema_name} has no properties in the generated OpenAPI"));
    let mut real: Vec<&str> = props.keys().map(String::as_str).collect();
    real.sort_unstable();
    let mut expected: Vec<&str> = fields.to_vec();
    expected.sort_unstable();
    assert_eq!(real, expected, "{schema_name} field set drifted from Sage");
}

#[test]
fn options_types_match_the_generated_openapi_field_sets() {
    assert_schema_fields(
        "OptionRecord",
        &[
            "launcher_id",
            "visible",
            "coin_id",
            "address",
            "amount",
            "underlying_asset",
            "underlying_amount",
            "underlying_coin_id",
            "strike_asset",
            "strike_amount",
            "expiration_seconds",
            "name",
            "created_height",
            "created_timestamp",
        ],
    );
    assert_schema_fields(
        "MintOption",
        &[
            "expiration_seconds",
            "underlying",
            "strike",
            "fee",
            "auto_submit",
        ],
    );
    assert_schema_fields(
        "MintOptionResponse",
        &["option_id", "summary", "coin_spends"],
    );
    assert_schema_fields(
        "GetOptions",
        &[
            "offset",
            "limit",
            "sort_mode",
            "ascending",
            "find_value",
            "include_hidden",
        ],
    );
    assert_schema_fields("GetOptionsResponse", &["options", "total"]);
    assert_schema_fields("OptionAsset", &["asset_id", "amount"]);
    assert_schema_fields(
        "TransferOptions",
        &["option_ids", "address", "fee", "clawback", "auto_submit"],
    );
    assert_schema_fields("ExerciseOptions", &["option_ids", "fee", "auto_submit"]);

    // The real `NetworkKind` enum has a third `unknown` variant this replica now includes.
    let spec = sage_openapi();
    let kind_enum = spec["components"]["schemas"]["NetworkKind"]["enum"]
        .as_array()
        .expect("NetworkKind enum array");
    let real: Vec<&str> = kind_enum.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(real, vec!["mainnet", "testnet", "unknown"]);
}

#[test]
fn actions_themes_and_network_types_match_the_generated_openapi_field_sets() {
    assert_schema_fields("ResyncCat", &["asset_id"]);
    assert_schema_fields("UpdateCat", &["record"]);
    assert_schema_fields("UpdateDid", &["did_id", "name", "visible"]);
    assert_schema_fields("UpdateOption", &["option_id", "visible"]);
    assert_schema_fields("UpdateNft", &["nft_id", "visible"]);
    assert_schema_fields("UpdateNftCollection", &["collection_id", "visible"]);
    assert_schema_fields("RedownloadNft", &["nft_id"]);
    assert_schema_fields(
        "IncreaseDerivationIndex",
        &["hardened", "index", "unhardened"],
    );
    assert_schema_fields("GetUserThemesResponse", &["themes"]);
    assert_schema_fields("GetUserThemeResponse", &["theme"]);
    // Verified/fixed by this vector: the real request has NO caller-supplied theme content.
    assert_schema_fields("SaveUserTheme", &["nft_id"]);
    assert_schema_fields("DeleteUserTheme", &["nft_id"]);
    assert_schema_fields("GetPeersResponse", &["peers"]);
    assert_schema_fields(
        "PeerRecord",
        &["ip_addr", "port", "peak_height", "user_managed"],
    );
    assert_schema_fields("AddPeer", &["ip"]);
    assert_schema_fields("RemovePeer", &["ip", "ban"]);
    assert_schema_fields("SetDiscoverPeers", &["discover_peers"]);
    assert_schema_fields("SetTargetPeers", &["target_peers"]);
    assert_schema_fields("SetNetwork", &["name"]);
    assert_schema_fields("SetNetworkOverride", &["fingerprint", "name"]);
    assert_schema_fields("SetDeltaSync", &["delta_sync"]);
    assert_schema_fields("SetDeltaSyncOverride", &["fingerprint", "delta_sync"]);
    assert_schema_fields("SetChangeAddress", &["fingerprint", "change_address"]);
}

#[test]
fn options_actions_themes_network_methods_are_real_sage_endpoints() {
    let spec = sage_openapi();
    let paths = spec["paths"].as_object().expect("paths object");
    for method in [
        "get_options",
        "get_option",
        "mint_option",
        "transfer_options",
        "exercise_options",
        "resync_cat",
        "update_cat",
        "update_did",
        "update_option",
        "update_nft",
        "update_nft_collection",
        "redownload_nft",
        "increase_derivation_index",
        "get_user_themes",
        "get_user_theme",
        "save_user_theme",
        "delete_user_theme",
        "get_peers",
        "add_peer",
        "remove_peer",
        "set_discover_peers",
        "set_target_peers",
        "set_network",
        "set_network_override",
        "get_networks",
        "get_network",
        "set_delta_sync",
        "set_delta_sync_override",
        "set_change_address",
    ] {
        assert!(
            paths.contains_key(&format!("/{method}")),
            "`{method}` is not a real Sage v0.12.11 endpoint"
        );
        assert!(WalletBackend::supports(method), "`{method}` must be served");
    }
}

#[test]
fn offer_mint_transfer_methods_are_real_sage_endpoints() {
    let catalogue: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(SAGE_ENDPOINTS).expect("endpoints.json parses");
    for method in [
        "make_offer",
        "take_offer",
        "view_offer",
        "combine_offers",
        "get_offers",
        "get_offer",
        "cancel_offer",
        "create_did",
        "bulk_mint_nfts",
        "transfer_nfts",
        "transfer_dids",
    ] {
        assert!(
            catalogue.contains_key(method),
            "method `{method}` is not in the pinned Sage v0.12.11 endpoints.json"
        );
        assert!(WalletBackend::supports(method), "`{method}` must be served");
    }
}

#[test]
fn offer_amount_and_summary_are_byte_identical() {
    // The `make_offer` requested/offered leg shape.
    let amt = OfferAmount {
        asset_id: None,
        amount: Amount::u64(500),
    };
    assert_eq!(
        serde_json::to_string(&amt).unwrap(),
        r#"{"asset_id":null,"amount":500}"#
    );

    // OfferSummary + OfferAsset + status, in Sage field/enum order.
    let summary = OfferSummary {
        fee: Amount::u64(0),
        maker: vec![OfferAsset {
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
            amount: Amount::u64(300),
            royalty: Amount::u64(0),
            nft_royalty: None,
            option_assets: None,
        }],
        taker: vec![],
        expiration_height: None,
        expiration_timestamp: None,
    };
    assert_eq!(
        serde_json::to_string(&summary).unwrap(),
        r#"{"fee":0,"maker":[{"asset":{"asset_id":null,"name":"Chia","ticker":"XCH","precision":12,"icon_url":null,"description":null,"is_sensitive_content":false,"is_visible":true,"revocation_address":null,"kind":"token"},"amount":300,"royalty":0,"nft_royalty":null,"option_assets":null}],"taker":[],"expiration_height":null,"expiration_timestamp":null}"#
    );
}

#[test]
fn offer_record_status_is_snake_case() {
    assert_eq!(
        serde_json::to_string(&OfferRecordStatus::Active).unwrap(),
        r#""active""#
    );
    assert_eq!(
        serde_json::to_string(&OfferRecordStatus::Cancelled).unwrap(),
        r#""cancelled""#
    );
    assert_eq!(
        serde_json::to_string(&OfferRecordStatus::Completed).unwrap(),
        r#""completed""#
    );
}

#[test]
fn make_offer_response_and_bulk_mint_response_are_byte_identical() {
    let mo = MakeOfferResponse {
        offer: "offer1abc".into(),
        offer_id: "deadbeef".into(),
    };
    assert_eq!(
        serde_json::to_string(&mo).unwrap(),
        r#"{"offer":"offer1abc","offer_id":"deadbeef"}"#
    );

    let bm = BulkMintNftsResponse {
        nft_ids: vec!["aa".into()],
        summary: TransactionSummary {
            fee: Amount::u64(0),
            inputs: vec![],
        },
        coin_spends: vec![],
    };
    assert_eq!(
        serde_json::to_string(&bm).unwrap(),
        r#"{"nft_ids":["aa"],"summary":{"fee":0,"inputs":[]},"coin_spends":[]}"#
    );
}

#[test]
fn take_offer_response_is_byte_identical() {
    let to = TakeOfferResponse {
        summary: TransactionSummary {
            fee: Amount::u64(1),
            inputs: vec![],
        },
        spend_bundle: SpendBundleJson {
            coin_spends: vec![],
            aggregated_signature: "c0".into(),
        },
        transaction_id: "abcd".into(),
    };
    assert_eq!(
        serde_json::to_string(&to).unwrap(),
        r#"{"summary":{"fee":1,"inputs":[]},"spend_bundle":{"coin_spends":[],"aggregated_signature":"c0"},"transaction_id":"abcd"}"#
    );
}

#[test]
fn mint_transfer_requests_deserialize_with_sage_defaults() {
    // create_did/transfer/cancel default auto_submit to FALSE (Sage `#[serde(default)]`).
    let cd: CreateDid = serde_json::from_str(r#"{"name":"me","fee":0}"#).unwrap();
    assert!(!cd.auto_submit, "create_did auto_submit defaults false");

    // make_offer defaults auto_import to TRUE (`#[serde(default = "yes")]`).
    let mo: MakeOffer =
        serde_json::from_str(r#"{"requested_assets":[],"offered_assets":[],"fee":0}"#).unwrap();
    assert!(mo.auto_import, "make_offer auto_import defaults true");
    assert!(mo.receive_address.is_none());

    // An NftMint with only URIs — every other field defaults.
    let m: NftMint = serde_json::from_str(r#"{"data_uris":["u"]}"#).unwrap();
    assert_eq!(m.royalty_ten_thousandths, 0);
    assert!(m.address.is_none());
    assert_eq!(m.data_uris, vec!["u".to_string()]);

    let tn: TransferNfts =
        serde_json::from_str(r#"{"nft_ids":["a"],"address":"xch1x","fee":0}"#).unwrap();
    assert!(!tn.auto_submit);
    assert!(tn.clawback.is_none());
}

#[test]
fn send_spend_group_methods_are_real_sage_endpoints() {
    let catalogue: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(SAGE_ENDPOINTS).expect("endpoints.json parses");
    for method in [
        "send_xch",
        "bulk_send_xch",
        "send_cat",
        "bulk_send_cat",
        "combine",
        "split",
        "multi_send",
        "sign_coin_spends",
        "view_coin_spends",
        "submit_transaction",
    ] {
        assert!(
            catalogue.contains_key(method),
            "send/spend method `{method}` is not in the pinned Sage v0.12.11 endpoints.json"
        );
        assert!(WalletBackend::supports(method), "`{method}` must be served");
    }
}

#[test]
fn coin_spend_json_is_byte_identical() {
    let cs = CoinSpendJson {
        coin: CoinJson {
            parent_coin_info: "aa".into(),
            puzzle_hash: "bb".into(),
            amount: Amount::u64(1),
        },
        puzzle_reveal: "ff01".into(),
        solution: "80".into(),
    };
    assert_eq!(
        serde_json::to_string(&cs).unwrap(),
        r#"{"coin":{"parent_coin_info":"aa","puzzle_hash":"bb","amount":1},"puzzle_reveal":"ff01","solution":"80"}"#
    );
}

#[test]
fn transaction_response_is_byte_identical() {
    // The `pub type …Response = TransactionResponse` shape shared by every spend builder.
    let resp = TransactionResponse {
        summary: TransactionSummary {
            fee: Amount::u64(0),
            inputs: vec![],
        },
        coin_spends: vec![],
    };
    assert_eq!(
        serde_json::to_string(&resp).unwrap(),
        r#"{"summary":{"fee":0,"inputs":[]},"coin_spends":[]}"#
    );
}

#[test]
fn spend_bundle_json_is_byte_identical() {
    let b = SpendBundleJson {
        coin_spends: vec![],
        aggregated_signature: "c0".into(),
    };
    assert_eq!(
        serde_json::to_string(&b).unwrap(),
        r#"{"coin_spends":[],"aggregated_signature":"c0"}"#
    );
}

#[test]
fn get_version_response_is_byte_identical() {
    let v = GetVersionResponse {
        version: "0.12.11".into(),
    };
    assert_eq!(
        serde_json::to_string(&v).unwrap(),
        r#"{"version":"0.12.11"}"#
    );
}

#[test]
fn derivation_record_is_byte_identical() {
    let d = DerivationRecord {
        index: 3,
        public_key: "b0abc".into(),
        address: "xch1abc".into(),
    };
    assert_eq!(
        serde_json::to_string(&d).unwrap(),
        r#"{"index":3,"public_key":"b0abc","address":"xch1abc"}"#
    );
}

#[test]
fn coin_record_matches_sage_field_order_and_null_omission() {
    let c = CoinRecord {
        coin_id: "cc".into(),
        address: "xch1".into(),
        amount: Amount::u64(1_000),
        transaction_id: None,
        offer_id: None,
        clawback_timestamp: None,
        created_height: Some(42),
        spent_height: None,
        spent_timestamp: None,
        created_timestamp: Some(1_700_000_000),
    };
    assert_eq!(
        serde_json::to_string(&c).unwrap(),
        r#"{"coin_id":"cc","address":"xch1","amount":1000,"transaction_id":null,"offer_id":null,"clawback_timestamp":null,"created_height":42,"spent_height":null,"spent_timestamp":null,"created_timestamp":1700000000}"#
    );
}

#[test]
fn token_record_xch_has_null_asset_id_and_number_amounts() {
    let t = TokenRecord {
        asset_id: None,
        name: Some("Chia".into()),
        ticker: Some("XCH".into()),
        precision: 12,
        description: None,
        icon_url: None,
        visible: true,
        balance: Amount::u64(5_000),
        selectable_balance: Amount::u64(5_000),
        revocation_address: None,
    };
    assert_eq!(
        serde_json::to_string(&t).unwrap(),
        r#"{"asset_id":null,"name":"Chia","ticker":"XCH","precision":12,"description":null,"icon_url":null,"visible":true,"balance":5000,"selectable_balance":5000,"revocation_address":null}"#
    );
}

#[test]
fn sync_status_response_matches_sage_shape() {
    let s = GetSyncStatusResponse {
        selectable_balance: Amount::u64(0),
        unit: Unit::xch(),
        synced_coins: 0,
        total_coins: 0,
        receive_address: "xch1recv".into(),
        burn_address: "xch1burn".into(),
        unhardened_derivation_index: 0,
        hardened_derivation_index: 0,
        checked_files: 0,
        total_files: 0,
        database_size: 0,
    };
    assert_eq!(
        serde_json::to_string(&s).unwrap(),
        r#"{"selectable_balance":0,"unit":{"ticker":"XCH","precision":12},"synced_coins":0,"total_coins":0,"receive_address":"xch1recv","burn_address":"xch1burn","unhardened_derivation_index":0,"hardened_derivation_index":0,"checked_files":0,"total_files":0,"database_size":0}"#
    );
}

#[test]
fn large_amount_serializes_as_string_above_js_safe_integer() {
    // A CAT total supply beyond 2^53-1 must be a JSON string (JS-safe), matching Sage.
    let big = MAX_JS_SAFE_INTEGER + 1;
    let t = GetTokenResponse {
        token: Some(TokenRecord {
            asset_id: Some("aa".into()),
            name: None,
            ticker: None,
            precision: 3,
            description: None,
            icon_url: None,
            visible: true,
            balance: Amount::u128(big as u128),
            selectable_balance: Amount::u64(0),
            revocation_address: None,
        }),
    };
    let json = serde_json::to_string(&t).unwrap();
    assert!(
        json.contains(r#""balance":"9007199254740992""#),
        "got {json}"
    );
    assert!(json.contains(r#""selectable_balance":0"#));
}

#[test]
fn sage_shaped_requests_deserialize_losslessly() {
    // A minimal get_coins request (Sage lets sort/filter/ascending/asset_id default).
    let r: GetCoins = serde_json::from_str(r#"{"offset":0,"limit":25}"#).unwrap();
    assert_eq!(r.sort_mode, CoinSortMode::CreatedHeight);
    assert_eq!(r.filter_mode, CoinFilterMode::Selectable);

    // get_key with a null fingerprint means "current wallet".
    let k: GetKey = serde_json::from_str(r#"{"fingerprint":null}"#).unwrap();
    assert!(k.fingerprint.is_none());
    let k2: GetKey = serde_json::from_str(r#"{}"#).unwrap();
    assert!(k2.fingerprint.is_none());
}
