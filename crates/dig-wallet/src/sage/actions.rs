//! Record-update actions (design A.5 "Actions", #205 PR4): `resync_cat`, `update_cat`,
//! `update_did`, `update_option`, `update_nft`, `update_nft_collection`, `redownload_nft`,
//! `increase_derivation_index`. Every method here is a DB-only mutation (no chain
//! interaction, no signing) — thin, validated wrappers over [`WalletDb`] that the RPC layer
//! ([`super::rpc`]) dispatches to after normalizing wire ids (hex/bech32m → stored hex).

use super::db::WalletDb;
use super::types::{IncreaseDerivationIndexResponse, TokenRecord};
use super::{Error, Result};

/// `resync_cat` — clear a CAT's cached display metadata, forcing a future re-fetch. The
/// coins/balance are untouched (this is metadata-only, mirroring Sage's "forget what we
/// cached about this asset's name/ticker/icon and re-resolve it").
pub async fn resync_cat(db: &WalletDb, asset_id: &str) -> Result<()> {
    db.clear_cat_metadata(asset_id).await?;
    Ok(())
}

/// `update_cat` — persist a CAT's display metadata from a caller-supplied [`TokenRecord`].
/// `record.asset_id` must be set (XCH has no CAT row to update).
pub async fn update_cat(db: &WalletDb, record: &TokenRecord) -> Result<()> {
    let asset_id = record
        .asset_id
        .as_deref()
        .ok_or_else(|| Error::api("update_cat requires a CAT asset_id (XCH has no CAT row)"))?;
    db.update_cat_metadata(
        asset_id,
        record.name.as_deref(),
        record.ticker.as_deref(),
        record.description.as_deref(),
        record.icon_url.as_deref(),
        record.visible,
    )
    .await?;
    Ok(())
}

/// `update_did` — set a DID's display name and/or visibility.
pub async fn update_did(
    db: &WalletDb,
    did_id: &str,
    name: Option<&str>,
    visible: bool,
) -> Result<()> {
    db.update_did_fields(did_id, name, visible).await?;
    Ok(())
}

/// `update_option` — set an option contract's visibility.
pub async fn update_option(db: &WalletDb, option_id: &str, visible: bool) -> Result<()> {
    db.update_option_visible(option_id, visible).await?;
    Ok(())
}

/// `update_nft` — set an NFT's visibility.
pub async fn update_nft(db: &WalletDb, nft_id: &str, visible: bool) -> Result<()> {
    db.update_nft_visible(nft_id, visible).await?;
    Ok(())
}

/// `update_nft_collection` — set an NFT collection's visibility.
pub async fn update_nft_collection(
    db: &WalletDb,
    collection_id: &str,
    visible: bool,
) -> Result<()> {
    db.update_nft_collection_visible(collection_id, visible)
        .await?;
    Ok(())
}

/// `redownload_nft` — clear an NFT's cached off-chain metadata JSON, forcing a future
/// re-fetch (on-chain URIs/hashes in the wire record are untouched; only the fetched-blob
/// cache is cleared).
pub async fn redownload_nft(db: &WalletDb, nft_id: &str) -> Result<()> {
    db.clear_nft_metadata_json(nft_id).await?;
    Ok(())
}

/// `increase_derivation_index` — raise the reported derivation-index floor for the selected
/// HD tree(s) so `get_sync_status`/`get_derivations` report at least `index` coverage, even
/// before any coin activity at those indices. At least one of `hardened`/`unhardened` must be
/// requested.
/// Raise the derivation floor(s), reporting the floors IN FORCE afterwards (dig-node#256).
///
/// A tree the request did not name reports `None` — "not asked", never a floor of 0. See
/// [`crate::sage::types::IncreaseDerivationIndexResponse`] for why this returns figures at all.
pub async fn increase_derivation_index(
    db: &WalletDb,
    hardened: Option<bool>,
    unhardened: Option<bool>,
    index: u32,
) -> Result<IncreaseDerivationIndexResponse> {
    let want_hardened = hardened.unwrap_or(false);
    let want_unhardened = unhardened.unwrap_or(false);
    if !want_hardened && !want_unhardened {
        return Err(Error::api(
            "increase_derivation_index requires hardened and/or unhardened to be true",
        ));
    }
    let mut out = IncreaseDerivationIndexResponse {
        hardened_floor: None,
        unhardened_floor: None,
    };
    if want_hardened {
        out.hardened_floor = Some(db.raise_derivation_floor(true, index).await?);
    }
    if want_unhardened {
        out.unhardened_floor = Some(db.raise_derivation_floor(false, index).await?);
    }
    Ok(out)
}

#[cfg(test)]
mod derivation_floor_tests {
    use super::*;

    /// **dig-node#256 — a clamped request must not report success (the money case).**
    ///
    /// The write is `MAX(col, ?)`, so asking for an index BELOW the current floor changes
    /// nothing. Under the shared empty `ActionResponse {}` the caller was told it succeeded, and
    /// addresses above the index they thought they had raised to stay unscanned — funds that are
    /// invisible with no error and no retry.
    ///
    /// The raise is asserted FIRST as the control. Without it a response that reported the
    /// REQUESTED index back would pass the second half, and an implementation that always
    /// reported the same figure would pass the first.
    #[tokio::test]
    async fn a_clamped_raise_reports_the_floor_in_force_not_the_one_requested() {
        let db = WalletDb::open_in_memory().await.unwrap();

        let up = increase_derivation_index(&db, None, Some(true), 500)
            .await
            .unwrap();
        assert_eq!(
            up.unhardened_floor,
            Some(500),
            "control: a genuine raise reports the new floor"
        );

        let down = increase_derivation_index(&db, None, Some(true), 5)
            .await
            .unwrap();
        assert_eq!(
            down.unhardened_floor,
            Some(500),
            "a request below the floor is a no-op, and the response must say so by reporting 500              — echoing back the requested 5 is the lie this ticket removes"
        );
    }

    /// A tree the request did not name reports `None`, never a floor of `0`.
    ///
    /// Zero is a real claim — *this tree scans no derived addresses* — so rendering "not asked"
    /// as zero is the unknown-as-a-number defect this whole batch is about, one field along.
    #[tokio::test]
    async fn an_unrequested_tree_reports_unknown_rather_than_a_floor_of_zero() {
        let db = WalletDb::open_in_memory().await.unwrap();

        let r = increase_derivation_index(&db, Some(true), None, 12)
            .await
            .unwrap();
        assert_eq!(r.hardened_floor, Some(12));
        assert_eq!(
            r.unhardened_floor, None,
            "the unhardened tree was not asked about; `Some(0)` would assert it scans nothing"
        );

        // Both trees at once, so the `None` above cannot be an artefact of the field never being
        // populated at all.
        let both = increase_derivation_index(&db, Some(true), Some(true), 20)
            .await
            .unwrap();
        assert_eq!(both.hardened_floor, Some(20));
        assert_eq!(both.unhardened_floor, Some(20));
    }

    /// A write that updates NO ROW is an error, not a quiet success (dig-node#256).
    ///
    /// `UPDATE … WHERE id = 0` against an absent settings row affects zero rows and `execute`
    /// returns `Ok`. That is the shape with no symptom at all: the floor is never raised and the
    /// caller is told it was. The seeded control in the same test proves the refusal is keyed on
    /// the missing row rather than on the method always failing.
    #[tokio::test]
    async fn a_zero_row_update_fails_rather_than_reporting_a_raise() {
        let db = WalletDb::open_in_memory().await.unwrap();
        assert!(
            increase_derivation_index(&db, None, Some(true), 7)
                .await
                .is_ok(),
            "control: with the settings row present the raise succeeds"
        );

        db.delete_network_settings_row_for_test().await.unwrap();

        assert!(
            increase_derivation_index(&db, None, Some(true), 7)
                .await
                .is_err(),
            "with no settings row nothing is written; reporting success here is the defect"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sage::db::CatRow;

    #[tokio::test]
    async fn resync_cat_clears_metadata() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_cat(&CatRow {
            asset_id: "a1".into(),
            name: Some("N".into()),
            ticker: Some("T".into()),
            precision: 3,
            description: None,
            icon_url: None,
            visible: true,
        })
        .await
        .unwrap();
        resync_cat(&db, "a1").await.unwrap();
        assert!(db.cat("a1").await.unwrap().unwrap().name.is_none());
    }

    #[tokio::test]
    async fn update_cat_requires_asset_id() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let record = TokenRecord {
            asset_id: None,
            name: Some("Chia".into()),
            ticker: Some("XCH".into()),
            precision: 12,
            description: None,
            icon_url: None,
            visible: true,
            balance: crate::sage::types::Amount::u64(0),
            selectable_balance: crate::sage::types::Amount::u64(0),
            revocation_address: None,
        };
        assert!(update_cat(&db, &record).await.is_err());
    }

    #[tokio::test]
    async fn update_cat_persists_metadata() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let record = TokenRecord {
            asset_id: Some("a2".into()),
            name: Some("My Token".into()),
            ticker: Some("MTK".into()),
            precision: 3,
            description: Some("d".into()),
            icon_url: Some("http://i".into()),
            visible: false,
            balance: crate::sage::types::Amount::u64(0),
            selectable_balance: crate::sage::types::Amount::u64(0),
            revocation_address: None,
        };
        update_cat(&db, &record).await.unwrap();
        let cat = db.cat("a2").await.unwrap().unwrap();
        assert_eq!(cat.name.as_deref(), Some("My Token"));
        assert!(!cat.visible);
    }

    #[tokio::test]
    async fn increase_derivation_index_requires_a_target_tree() {
        let db = WalletDb::open_in_memory().await.unwrap();
        assert!(increase_derivation_index(&db, None, None, 10)
            .await
            .is_err());
        assert!(increase_derivation_index(&db, Some(false), Some(false), 10)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn increase_derivation_index_raises_the_requested_trees() {
        let db = WalletDb::open_in_memory().await.unwrap();
        increase_derivation_index(&db, Some(true), Some(false), 20)
            .await
            .unwrap();
        assert_eq!(db.max_derivation_index(true).await.unwrap(), 20);
        assert_eq!(db.max_derivation_index(false).await.unwrap(), 0);

        increase_derivation_index(&db, Some(false), Some(true), 5)
            .await
            .unwrap();
        assert_eq!(db.max_derivation_index(false).await.unwrap(), 5);
    }
}
