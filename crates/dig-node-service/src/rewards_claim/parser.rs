//! The launch-comment parser (SPEC §1.3) — the only place a distributor's launch spend is tied to
//! content, so a wrong parse here is a wrong claim everywhere downstream.
//!
//! `dig-rewards:v1:<store_id_hex>:<root_hex>`, each half exactly 64 lowercase hex characters. A
//! writer MUST emit lowercase; a reader MUST accept either case and compare the 32 BYTES, never the
//! text (SPEC §1.3). A comment that does not parse is "not a DIG rewards distributor" — not an
//! error (SPEC §1.3 clause 3).

use chia_protocol::Bytes32;

use super::types::DiscoveredDistributor;

const PREFIX: &str = "dig-rewards:v1:";

/// Parse a launch comment into the `(store_id, root)` it names, or `None` if it is not a DIG
/// rewards distributor's comment. `launcher_id` is threaded through unchanged — this function only
/// interprets the comment string.
#[must_use]
pub fn parse_launch_comment(launcher_id: Bytes32, comment: &str) -> Option<DiscoveredDistributor> {
    let rest = comment.strip_prefix(PREFIX)?;
    let (store_hex, root_hex) = rest.split_once(':')?;
    let store_id = parse_hex32(store_hex)?;
    let root = parse_hex32(root_hex)?;
    Some(DiscoveredDistributor {
        launcher_id,
        store_id,
        root,
    })
}

/// Exactly 64 hex characters (either case), compared as the 32 bytes they denote — never as text.
fn parse_hex32(hex: &str) -> Option<Bytes32> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex, &mut bytes).ok()?;
    Some(Bytes32::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lid() -> Bytes32 {
        Bytes32::from([7u8; 32])
    }

    #[test]
    fn table_driven_launch_comment_parsing() {
        let store = "a".repeat(64);
        let root = "b".repeat(64);
        let store_upper = "A".repeat(64);

        let cases: &[(&str, bool)] = &[
            ("valid lowercase", true),
            ("valid uppercase halves", true),
            ("wrong prefix", false),
            ("wrong version", false),
            ("short store half", false),
            ("long store half", false),
            ("non-hex store half", false),
            ("empty comment", false),
            ("empty halves", false),
        ];

        let comments: &[String] = &[
            format!("dig-rewards:v1:{store}:{root}"),
            format!("dig-rewards:v1:{store_upper}:{root}"),
            format!("dig-mirror:v1:{store}:{root}"),
            format!("dig-rewards:v2:{store}:{root}"),
            format!("dig-rewards:v1:{}:{root}", &store[..63]),
            format!("dig-rewards:v1:{store}a:{root}"),
            format!("dig-rewards:v1:{}:{root}", "z".repeat(64)),
            String::new(),
            "dig-rewards:v1::".to_string(),
        ];

        for ((name, expect_some), comment) in cases.iter().zip(comments.iter()) {
            let got = parse_launch_comment(lid(), comment);
            assert_eq!(got.is_some(), *expect_some, "case: {name} ({comment:?})");
        }
    }

    #[test]
    fn parse_compares_bytes_not_text_case() {
        let store = "ab".repeat(32);
        let root = "cd".repeat(32);
        let lower = parse_launch_comment(lid(), &format!("dig-rewards:v1:{store}:{root}")).unwrap();
        let upper = parse_launch_comment(
            lid(),
            &format!(
                "dig-rewards:v1:{}:{}",
                store.to_uppercase(),
                root.to_uppercase()
            ),
        )
        .unwrap();
        assert_eq!(lower.store_id, upper.store_id);
        assert_eq!(lower.root, upper.root);
    }
}
