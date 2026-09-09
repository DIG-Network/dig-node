//! The DIG-Network/dig_ecosystem#3252 seam — defined here, wired to nothing (SPEC §13.2).

use async_trait::async_trait;
use chia_protocol::Bytes32;

/// An UNTRUSTED pointer to a distributor (SPEC §13.2 clause 1) — exactly like
/// `unverified_mirror_coin_id`. It MUST NOT admit an entry, MUST NOT rank a candidate and MUST NOT
/// be a claim's authority. Every property is re-derived from the chain via
/// [`super::port::ClaimChainPort::resolve_launch_comment`] before this hint's launcher id becomes a
/// candidate. DIG-Network/dig_ecosystem#3252 supplies the dig-gossip implementation by extending the
/// holdings-announce wire (opcode 222).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributorHint {
    pub launcher_id: Bytes32,
}

/// A source of untrusted distributor pointers (SPEC §13.2).
#[async_trait]
pub trait DistributorHintSource: Send + Sync {
    async fn hints(&self) -> Vec<DistributorHint>;
}

/// The MVP wiring: no hints. SPEC §13.2 clause 2 — a peer that never hears a hint MUST still find
/// and claim via §13.1, so this changes no outcome; it only removes a latency shortcut this lane
/// does not build.
pub struct NoHintSource;

#[async_trait]
impl DistributorHintSource for NoHintSource {
    async fn hints(&self) -> Vec<DistributorHint> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_hint_source_yields_nothing() {
        assert!(NoHintSource.hints().await.is_empty());
    }
}
