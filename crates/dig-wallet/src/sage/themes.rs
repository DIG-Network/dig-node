//! The Sage-desktop-UI theme store (design A.5 "Themes", #205 PR4): `get_user_themes`,
//! `get_user_theme`, `save_user_theme`, `delete_user_theme`. These endpoints are
//! Sage-desktop-UI-only in origin (design Part F "MAY / N-A") but are included here as an
//! opaque, DB-backed key-value store keyed by NFT id, so a dig-node-hosted client that wants
//! to remember a per-NFT UI theme has somewhere to put it.
//!
//! **Wire shape, verified against the pinned v0.12.11 generated OpenAPI (design A.10):**
//! `save_user_theme`'s request carries ONLY `nft_id` — no caller-supplied theme content. The
//! real Sage desktop derives the theme from the NFT's own artwork (color extraction) rather
//! than accepting an arbitrary string; this backend has no image/color-extraction pipeline,
//! so [`save_user_theme`] persists [`DERIVED_THEME_PLACEHOLDER`] instead of a real derived
//! theme — `get_user_theme`/`get_user_themes` still report the NFT as themed (parity for
//! "has a theme been saved"), but the placeholder is not a rendered color scheme. Real
//! derivation is a tracked follow-on once an image pipeline exists.

use super::db::WalletDb;
use super::Result;

/// The stored value [`save_user_theme`] uses in place of a real image-derived theme (see the
/// module docs). Opaque; callers should treat this as "themed with an unspecified theme" and
/// not attempt to render it as a color scheme.
pub const DERIVED_THEME_PLACEHOLDER: &str = "auto";

/// `get_user_themes` — every NFT id with a saved theme.
pub async fn get_user_themes(db: &WalletDb) -> Result<Vec<String>> {
    Ok(db.all_theme_nft_ids().await?)
}

/// `get_user_theme` — one NFT's saved theme, if any (see the module docs re: the placeholder
/// content this backend stores).
pub async fn get_user_theme(db: &WalletDb, nft_id: &str) -> Result<Option<String>> {
    Ok(db.user_theme(nft_id).await?)
}

/// `save_user_theme` — mark `nft_id` as themed (see the module docs: this backend has no
/// image/color-extraction pipeline, so it persists [`DERIVED_THEME_PLACEHOLDER`] rather than
/// a real derived theme).
pub async fn save_user_theme(db: &WalletDb, nft_id: &str) -> Result<()> {
    db.save_user_theme(nft_id, DERIVED_THEME_PLACEHOLDER)
        .await?;
    Ok(())
}

/// `delete_user_theme` — delete an NFT's saved theme (a no-op if none is saved).
pub async fn delete_user_theme(db: &WalletDb, nft_id: &str) -> Result<()> {
    db.delete_user_theme(nft_id).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn themes_round_trip() {
        let db = WalletDb::open_in_memory().await.unwrap();
        assert!(get_user_themes(&db).await.unwrap().is_empty());
        assert!(get_user_theme(&db, "nft1").await.unwrap().is_none());

        save_user_theme(&db, "nft1").await.unwrap();
        assert_eq!(get_user_themes(&db).await.unwrap(), vec!["nft1"]);
        assert_eq!(
            get_user_theme(&db, "nft1").await.unwrap().as_deref(),
            Some(DERIVED_THEME_PLACEHOLDER)
        );

        delete_user_theme(&db, "nft1").await.unwrap();
        assert!(get_user_theme(&db, "nft1").await.unwrap().is_none());
        assert!(get_user_themes(&db).await.unwrap().is_empty());
    }
}
