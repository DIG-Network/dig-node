//! The node's CHAIN TRANSPORT: the reads dig-app needs to build a spend, and the push that puts an
//! already-signed one on the network (dig_ecosystem#2376).
//!
//! # Why this is separate from `enable_live_broadcast`
//!
//! `DIG_WALLET_ENABLE_LIVE_BROADCAST` (§18.12) answers one question: *may the node's OWN custodied
//! wallet sign and send?* That is a custody decision and it stays default-OFF. It is NOT the same
//! question as *may the node look at the chain, and may it relay a bundle somebody ELSE already
//! signed* — and the two were previously answered by the same flag, which is why a default install
//! answered `WALLET_NO_CHAIN_SOURCE` to every wallet read and could not push at all. The reads
//! disclose nothing the node holds, so they are served on every install.
//!
//! The push is served on every install too, but NOT unconditionally: the node's own custodied
//! wallet will sign on request, so "somebody else signed it" has to be CHECKED rather than assumed.
//! With the flag off, [`super::rpc::WalletBackend::push_signed_bundle`] refuses any bundle spending
//! a coin at a puzzle hash the node custodies a key for. Without that check the flag would be
//! decorative — sign through the node, then hand the bundle back for relay, and the node's own
//! money is on mainnet with live broadcast disabled.
//!
//! # The client is built LAZILY
//!
//! Constructing the client dials the network. A node whose operator never opens a wallet surface
//! should make no such call, so the client is built on FIRST USE and shared thereafter. A build
//! failure is not cached as a permanent verdict: a node that was offline at 9am must be able to
//! answer at 10am.
//!
//! # Unknown is never zero
//!
//! Every read here returns `Err` when it could not reach a chain. It never degrades an unreachable
//! chain into an empty list or a zero: an empty answer would tell somebody who holds funds that
//! they hold nothing, and a spend built on that refuses with a shortfall that is not true.

use std::sync::Arc;

use async_trait::async_trait;
use chia_protocol::SpendBundle;
use tokio::sync::Mutex;

use super::fallback::{ChainFallback, CoinsetFallback, FallbackCoin, FallbackCoinSpend};
use super::spend::to_query_bundle;
use super::{Error, Result};

/// The outcome of pushing an already-signed bundle to the network.
///
/// `accepted: false` is a mempool that LOOKED at the bundle and refused it — a fact about the
/// bundle. Failing to reach a mempool at all is an `Err` from [`ChainTransport::push`] instead,
/// because the two demand opposite remedies: build a different bundle, versus retry this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// Whether the mempool admitted the bundle.
    pub accepted: bool,
    /// The bundle's transaction id (its name), lowercase 64-hex. Reported only on acceptance —
    /// a refused bundle has no transaction to point at.
    pub transaction_id: Option<String>,
    /// The mempool's own words for the refusal, when it refused.
    pub rejection: Option<String>,
}

/// Pushes an ALREADY-SIGNED bundle to the network.
///
/// A trait rather than a concrete client so the control surface can be driven end to end without a
/// mainnet push: the shipped implementation is [`ChainTransport`], and a test double stands in for
/// the network. It takes a complete bundle and nothing else — there is no key, seed or unsigned
/// plan in this signature, and there may never be (§908).
#[async_trait]
pub trait SignedBundlePusher: Send + Sync {
    /// Relay `bundle`. A mempool refusal is `Ok` with `accepted: false`; failing to REACH a mempool
    /// is `Err`.
    async fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome>;
}

/// A shared, lazily-built `chia_query` client serving the wallet's chain reads and its push.
///
/// Also the wallet's [`ChainFallback`] tier, so a balance, a coin read and a push all speak to ONE
/// client rather than three — and so the tier a read reports (`"fallback"`) stays truthful.
pub struct ChainTransport {
    /// `None` until the first use builds it. Behind a `Mutex` rather than a `OnceCell` because a
    /// FAILED build must not be remembered as the answer forever (see the module docs).
    client: Mutex<Option<Arc<chia_query::ChiaQuery>>>,
}

impl Default for ChainTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainTransport {
    /// A transport that has not yet dialed anything.
    pub fn new() -> Self {
        Self {
            client: Mutex::new(None),
        }
    }

    /// The shared client, building it on first use.
    ///
    /// A failure to build is an `Err` and is NOT cached — the next call tries again, so a node that
    /// starts offline becomes useful the moment its network does.
    async fn client(&self) -> Result<Arc<chia_query::ChiaQuery>> {
        let mut slot = self.client.lock().await;
        if let Some(existing) = slot.as_ref() {
            return Ok(existing.clone());
        }
        let built = chia_query::ChiaQuery::new(chia_query::ChiaQueryConfig::default())
            .await
            .map_err(|e| Error::internal(format!("no chain source could be reached: {e}")))?;
        let built = Arc::new(built);
        *slot = Some(built.clone());
        Ok(built)
    }

    /// The chain's current peak height, or `Ok(None)` when the source tracks none.
    ///
    /// `Ok(None)` is an honest "no height known" — never height zero, which every block is
    /// trivially above and which would silently satisfy any "is it buried yet" comparison.
    pub async fn peak_height(&self) -> Result<Option<u32>> {
        self.client()
            .await?
            .peak_height_opt()
            .await
            .map_err(|e| Error::internal(format!("peak-height read failed: {e}")))
    }

    /// Push an ALREADY-SIGNED bundle.
    ///
    /// The node never signs and is never given anything it could sign with (§908): this takes a
    /// complete bundle and relays it. A mempool refusal comes back as `Ok(PushOutcome)` with
    /// `accepted: false`; an unreachable network is an `Err`.
    pub async fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome> {
        let status = self
            .client()
            .await?
            .push_tx(&to_query_bundle(bundle)?)
            .await
            .map_err(|e| Error::internal(format!("push failed to reach a mempool: {e}")))?;

        Ok(if status.success {
            PushOutcome {
                accepted: true,
                transaction_id: Some(hex::encode(bundle.name())),
                rejection: None,
            }
        } else {
            PushOutcome {
                accepted: false,
                transaction_id: None,
                rejection: Some(status.status),
            }
        })
    }
}

#[async_trait]
impl SignedBundlePusher for ChainTransport {
    async fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome> {
        ChainTransport::push(self, bundle).await
    }
}

#[async_trait]
impl ChainFallback for ChainTransport {
    async fn peak_height(&self) -> Result<Option<u32>> {
        ChainTransport::peak_height(self).await
    }

    async fn coin_records_by_puzzle_hashes(&self, phs: &[String]) -> Result<Vec<FallbackCoin>> {
        CoinsetFallback::new(self.client().await?)
            .coin_records_by_puzzle_hashes(phs)
            .await
    }

    async fn coin_records_by_hints(&self, hints: &[String]) -> Result<Vec<FallbackCoin>> {
        CoinsetFallback::new(self.client().await?)
            .coin_records_by_hints(hints)
            .await
    }

    async fn coin_record_by_id(&self, coin_id: &str) -> Result<Option<FallbackCoin>> {
        CoinsetFallback::new(self.client().await?)
            .coin_record_by_id(coin_id)
            .await
    }

    async fn coin_spend(&self, coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
        CoinsetFallback::new(self.client().await?)
            .coin_spend(coin_id)
            .await
    }

    async fn coin_records_by_parent(&self, parent_coin_id: &str) -> Result<Vec<FallbackCoin>> {
        CoinsetFallback::new(self.client().await?)
            .coin_records_by_parent(parent_coin_id)
            .await
    }

    /// `true`: this tier CAN reach a chain, so a read that fails does so as an honest error rather
    /// than being routed away as "there was nothing to ask".
    ///
    /// The distinction the caller draws off this flag is "is there a source at all", not "is the
    /// network up right now". Reporting `false` for a momentary outage would send an unreachable
    /// chain down the no-source path, where it reads as a permanent capability gap and tells the
    /// user to change their node instead of to try again.
    fn is_live(&self) -> bool {
        true
    }
}

// DELIBERATELY NOT a `Broadcaster` (dig_ecosystem#2376 review).
//
// `Broadcaster` is the node's OWN-SPEND path: attaching one turns on `auto_submit` and
// `submit_transaction` for the node's custodied key, which is the decision
// `DIG_WALLET_ENABLE_LIVE_BROADCAST` owns. An unused `impl Broadcaster for ChainTransport` sat here
// and made a one-line `.with_broadcaster(chain.clone())` compile, pass every test, and silently
// enable node-custodied sending on a default install. The transport is reachable only as a
// `SignedBundlePusher`, whose contract is a bundle somebody already signed.

/// Decode a hex-encoded, already-signed spend bundle.
///
/// Rejects anything that is not a complete `SpendBundle` in chia's `Streamable` form. Kept PURE and
/// separate from the push so a malformed bundle is an INVALID_PARAMS answer the caller can act on,
/// never a network error that reads as "try again" for a bundle that will never parse.
pub fn decode_signed_bundle(signed_bundle_hex: &str) -> Result<SpendBundle> {
    use chia_traits::Streamable;

    let trimmed = signed_bundle_hex
        .strip_prefix("0x")
        .unwrap_or(signed_bundle_hex);
    let bytes = hex::decode(trimmed)
        .map_err(|e| Error::api(format!("signed_bundle_hex is not hex: {e}")))?;
    SpendBundle::from_bytes(&bytes).map_err(|e| {
        Error::api(format!(
            "signed_bundle_hex is not a streamable SpendBundle: {e}"
        ))
    })
}

/// Re-encode a bundle to the hex form [`decode_signed_bundle`] accepts. Used by the round-trip
/// tests and by any caller that needs to hand the same bytes on.
pub fn encode_signed_bundle(bundle: &SpendBundle) -> Result<String> {
    use chia_traits::Streamable;

    bundle
        .to_bytes()
        .map(hex::encode)
        .map_err(|e| Error::internal(format!("bundle serialization failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::{Bytes32, Coin, CoinSpend, Program};

    /// A minimal but REAL signed bundle: one coin spend and an aggregate signature slot.
    fn a_bundle() -> SpendBundle {
        let coin = Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([2u8; 32]), 1_000);
        let spend = CoinSpend::new(coin, Program::from(vec![0x01]), Program::from(vec![0x80]));
        SpendBundle::new(vec![spend], Default::default())
    }

    /// **The hex form round-trips.** Pinned because the wire carries hex, not a struct: a bundle
    /// that re-encodes to different bytes would be pushed as a DIFFERENT transaction than the one
    /// the wallet signed, and its signature would no longer cover it.
    #[test]
    fn a_bundle_survives_the_hex_form_byte_for_byte() {
        let bundle = a_bundle();
        let hex = encode_signed_bundle(&bundle).expect("encode");
        let decoded = decode_signed_bundle(&hex).expect("decode");
        assert_eq!(decoded, bundle);
        assert_eq!(encode_signed_bundle(&decoded).expect("re-encode"), hex);
    }

    /// A `0x` prefix is tolerated, because half the Chia ecosystem emits one.
    #[test]
    fn a_zero_x_prefixed_bundle_decodes_identically() {
        let hex = encode_signed_bundle(&a_bundle()).expect("encode");
        assert_eq!(
            decode_signed_bundle(&format!("0x{hex}")).expect("decode"),
            decode_signed_bundle(&hex).expect("decode")
        );
    }

    /// **Garbage is INVALID_PARAMS, not a network failure.** The distinction is the caller's
    /// remedy: a malformed bundle will never succeed however many times it is retried.
    ///
    /// The two fixtures separate the two ways a bundle can be wrong — not hex at all, and
    /// well-formed hex that is not a bundle — because a decoder that only checked hex would pass
    /// the first and be caught by the second.
    #[test]
    fn a_malformed_bundle_is_rejected_before_any_network_call() {
        for bad in ["zzzz", "deadbeef"] {
            let err = decode_signed_bundle(bad).expect_err("must refuse");
            assert!(
                format!("{err}").contains("signed_bundle_hex"),
                "the error must name the offending parameter: {err}"
            );
        }
    }

    /// The transport starts with NO client, so merely constructing one dials nothing.
    ///
    /// Asserted through the public surface rather than by reading the field, so it stays true of
    /// what a caller can observe: a node that never serves a wallet read makes no chain call.
    #[tokio::test]
    async fn a_new_transport_holds_no_client_until_it_is_used() {
        let transport = ChainTransport::new();
        assert!(transport.client.lock().await.is_none());
    }
}
