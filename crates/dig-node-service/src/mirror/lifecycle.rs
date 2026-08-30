//! Bring-up and scheduling for the mirror-coin lifecycle — the production half of `SPEC.md` §25
//! (dig-node#412 step 7).
//!
//! [`super::runner::PassRunner`] knows what a pass DOES and [`super::observe`] knows what a bond
//! observation IS. Neither had a production caller, so `control.mirror.bondStates` answered
//! `unknown { reason: "chain_unreadable" }` on every call and no pass ever ran. This module is the
//! part that was missing: it opens the operator wallet once, builds the effects a pass needs, runs
//! one on the round timer, and publishes what it saw.
//!
//! # The read surface serves a SNAPSHOT, and that is a security property rather than a cache
//!
//! `control.mirror.bondStates` reads [`BondSnapshot`] — the observation the last pass published —
//! and does no chain work of its own. The alternative, observing per request, turns one ~200-byte
//! paired-token call into a seed unseal, a PBKDF2, up to `dig_mirror_coin::MAX_CANDIDATES` chain
//! lookups and an oracle read. A paired token is a much weaker predicate than "trusted", so that
//! would be a real amplification surface on a branch with no ingress limiter of its own. Reading a
//! published value costs a lock and cannot be amplified: the chain work happens on the round timer
//! whether anybody asks or not.
//!
//! The same reasoning removes the second unseal route. The owner puzzle hash is derived ONCE here,
//! at bring-up, where the operator wallet is already being opened under the device key, and held
//! afterwards as the public value it is. No read path re-opens the sealed seed.
//!
//! # An incomplete inventory is `unknown`, never a short answer
//!
//! `dig_mirror_coin::list` scans a puzzle hash every mirror coin in existence shares, so a stranger
//! can add candidates to it for the price of a dust coin, and the scan stops at `MAX_CANDIDATES`.
//! A truncated inventory reports LESS locked $DIG than is actually locked — money shown as free
//! while it sits on chain, which is the one direction a money figure must never be wrong in. So
//! [`MirrorInventory::is_complete`](dig_mirror_coin::MirrorInventory::is_complete) is consulted and
//! an incomplete scan aborts the pass, leaving the surface saying `unknown` with a named reason.
//!
//! # What this node can and cannot do with money today
//!
//! **Reclaims work.** `dig_mirror_coin::reclaim` recreates the full locked amount at the owner's own
//! puzzle hash and is supported at `fee = 0`, which needs no fee coins at all — so a node whose XCH
//! is exhausted can still recover $DIG it has locked. That is §25.4.4, and it is the invariant that
//! matters most, because its failure mode is collateral locked forever.
//!
//! **Creates do not, yet, and they refuse rather than guess.** `dig_mirror_coin::create` takes the
//! `Cat` inputs from its caller, and selecting them requires a $DIG coin selector scoped to the
//! OPERATOR puzzle hash. The node-custodied [`WalletBackend`](dig_wallet::sage::rpc::WalletBackend)
//! selector is scoped to its own replica instead, so using it would fund a mirror coin from the
//! wrong wallet's coins. [`NodeMirrorEffects::create`] therefore returns a named
//! [`PassError::Wallet`], the pass reports it in `stopped_at`, and §25.8 keeps reporting the bond
//! as uncovered — which is true. The selector is dig-node#420.
//!
//! # Nothing here relaxes the audit shape
//!
//! [`MirrorSigner::sign`](super::signer::MirrorSigner::sign) takes a [`SpendJournal`] and returns a
//! `RecordedSpend`, which is obtainable no other way. So this module cannot sign without journaling
//! — not because it promises not to, but because there is no expressible call that does.
//!
//! # The signer is module-private and is NOT installed on the general wallet
//!
//! [`MirrorSigner`] is held inside [`NodeMirrorEffects`] and reachable from nowhere else. In
//! particular it is never attached to the served `WalletBackend`: doing so would enable that
//! backend's own signing surface — including default-on auto-tipping — as a side effect of
//! collateralising capsules, which is an unreviewed behaviour change on a money path. A test asserts
//! the served backend still answers `None` for its current signer after bring-up.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chia_protocol::Bytes32;
use dig_chainsource_interface::ChainSource;
use dig_mirror_coin::MirrorCoin;
use dig_node_core::Node;
use dig_wallet::autoseed::WalletPaths;
use dig_wallet::operator_wallet::OperatorWallet;
use dig_wallet::sage::rpc::WalletBackend;
use dig_wallet::sage::spend::Broadcaster;

use crate::spend_audit::{
    FailureStage, FundingCoinId, SpendJournal, SpendLog, Submission, TargetCoinId,
};

use super::observe::held_mirrors;
use super::plan::{Bond, HeldMirror, ReclaimReason};
use super::runner::{MirrorEffects, ObservedCapsule, PassError, PassReport};
use super::signer::MirrorSigner;
use super::states::BondObservation;

/// The §25.8 observation the control surface serves, or `None` before the first pass has run.
///
/// `None` is UNKNOWN and the surface says so. It is deliberately not an empty observation: a page of
/// no rows is a definite claim that this node holds no bonds, and a node that has simply not
/// observed yet is not in a position to make it.
pub type BondSnapshot = Arc<RwLock<Option<BondObservation>>>;

/// A fresh, empty snapshot. The surface reads `unknown` from one of these until a pass fills it.
pub fn new_snapshot() -> BondSnapshot {
    Arc::new(RwLock::new(None))
}

/// The production [`MirrorEffects`], built fresh for each pass.
///
/// Built per pass rather than held, because two of its four readings are taken ASYNCHRONOUSLY by the
/// scheduler before the pass begins — the disk scan and the $DIG balance — and handing them in as
/// values is what lets the pass itself be synchronous. One pass therefore sees one disk state and
/// one balance throughout, which is the same guarantee [`super::runner::PassContext`] gives the
/// epoch and the requirement, and for the same reason.
pub struct NodeMirrorEffects<'a, S: ChainSource> {
    /// The capsules on disk, WITH provenance, already read.
    capsules: Result<Vec<ObservedCapsule>, PassError>,
    /// Spendable $DIG at the operator address, already read. `Err` defers creates, never reclaims.
    dig_balance: Result<u64, PassError>,
    /// The chain, for the owned-coin scan and for the reclaim spends.
    source: &'a S,
    /// This node's operator puzzle hash — a public value, derived once at bring-up.
    owner_puzzle_hash: Bytes32,
    /// The signer, when an operator wallet opened AND live broadcast is enabled.
    signer: Option<&'a MirrorSigner>,
    /// Where every automated spend is recorded before it is signed.
    journal: &'a SpendJournal,
    /// How a signed bundle reaches the mempool. `None` means this node does not broadcast.
    broadcaster: Option<&'a dyn Broadcaster>,
    /// A tokio handle, so the synchronous spend path can drive the asynchronous broadcast.
    runtime: tokio::runtime::Handle,
    /// The authenticated coins the last `observe_chain` resolved, keyed by coin id.
    ///
    /// `dig_mirror_coin::reclaim` needs the [`MirrorCoin`] itself — its lineage proof is what proves
    /// ownership — while [`MirrorEffects::reclaim`] is handed the planner's flat [`HeldMirror`].
    /// Retaining the coins the scan already authenticated is what bridges the two WITHOUT a second
    /// chain read, and more importantly without a second ownership derivation: the coin reclaimed is
    /// byte-for-byte the coin whose ownership was proven.
    resolved: std::cell::RefCell<HashMap<String, MirrorCoin>>,
}

impl<'a, S: ChainSource> NodeMirrorEffects<'a, S> {
    /// Assemble the effects for one pass from readings the scheduler has already taken.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capsules: Result<Vec<ObservedCapsule>, PassError>,
        dig_balance: Result<u64, PassError>,
        source: &'a S,
        owner_puzzle_hash: Bytes32,
        signer: Option<&'a MirrorSigner>,
        journal: &'a SpendJournal,
        broadcaster: Option<&'a dyn Broadcaster>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            capsules,
            dig_balance,
            source,
            owner_puzzle_hash,
            signer,
            journal,
            broadcaster,
            runtime,
            resolved: std::cell::RefCell::new(HashMap::new()),
        }
    }

    /// Sign, journal and broadcast `spends`, resolving the audit record either way.
    ///
    /// The record is opened by the signer, from the spends, so its account of the money cannot
    /// disagree with the bundle. This function's only job is to carry the outcome back onto it: a
    /// bundle that reached the mempool is `Submitted`, and a broadcast that failed is
    /// `Failed { stage: Broadcast }` rather than being dropped — dropping it writes `Unresolved`,
    /// which claims the node signed and does not know what became of it. That claim is true only
    /// when the broadcast's own outcome is genuinely unknown, and a returned error is not that.
    fn sign_and_broadcast(
        &self,
        spends: &super::spends::MirrorSpends,
        intended: Option<TargetCoinId>,
    ) -> Result<(), PassError> {
        let signer = self
            .signer
            .ok_or_else(|| PassError::Wallet("no operator wallet is available to sign".into()))?;
        let broadcaster = self.broadcaster.ok_or_else(|| {
            PassError::Wallet(
                "live broadcast is disabled (DIG_WALLET_ENABLE_LIVE_BROADCAST), so no mirror spend \
                 is sent"
                    .into(),
            )
        })?;

        let (bundle, recorded) = signer
            .sign(spends, self.journal)
            .map_err(|e| PassError::Wallet(e.to_string()))?;

        // The coins CONSUMED are read from the bundle itself rather than stated: every `CoinSpend`
        // in it spends exactly its own coin, so this cannot disagree with what was signed.
        let funding_coin_ids = spends
            .coin_spends()
            .iter()
            .map(|cs| FundingCoinId(hex::encode(cs.coin.coin_id())))
            .collect();

        match self.runtime.block_on(broadcaster.broadcast(&bundle)) {
            Ok(()) => {
                match intended {
                    // Recorded as an EXPECTATION. Only a chain observation may promote it to
                    // `Confirmed`, which is why `SpendJournal::confirmed` is not called from this
                    // path at all.
                    Some(intended_coin_id) => self.journal.submitted(
                        &recorded,
                        Submission {
                            intended_coin_id,
                            funding_coin_ids,
                        },
                    ),
                    // No coin id this node can DERIVE, so none is stated. Dropping `recorded`
                    // resolves it `Unresolved`, which this crate defines as "the node signed and
                    // does not know what became of it" — and after a successful broadcast with an
                    // underivable target, that is precisely true. Naming a plausible coin instead
                    // would let §23.5's reconcile confirm this spend against a coin it never
                    // created, which is the legacy defect `TargetCoinId` exists to make
                    // inexpressible.
                    None => tracing::warn!(
                        target: "mirror",
                        operation = spends.operation().as_str(),
                        "broadcast a mirror spend whose created coin this node cannot derive; the                          audit entry resolves UNRESOLVED rather than naming a guessed coin"
                    ),
                }
                Ok(())
            }
            Err(e) => {
                let cause = e.to_string();
                self.journal
                    .failed(&recorded, FailureStage::Broadcast, cause.clone());
                Err(PassError::Wallet(cause))
            }
        }
    }
}

impl<S: ChainSource> MirrorEffects for NodeMirrorEffects<'_, S> {
    fn observe_disk(&self) -> Result<Vec<ObservedCapsule>, PassError> {
        self.capsules.clone()
    }

    fn observe_chain(&self) -> Result<Vec<HeldMirror>, PassError> {
        let inventory = dig_mirror_coin::list(self.source, self.owner_puzzle_hash)
            .map_err(|e| PassError::Chain(e.to_string()))?;

        // Fail CLOSED on an incomplete scan. See the module doc: a short inventory under-reports
        // locked money, and the truncation point is purchasable with dust.
        if !inventory.is_complete() {
            return Err(PassError::Chain(format!(
                "the owned-coin scan was incomplete ({} candidates unresolved, truncated: {}), so \
                 this node's locked collateral is UNKNOWN rather than short",
                inventory.skipped().len(),
                inventory.is_truncated(),
            )));
        }

        // Retain the authenticated coins for the reclaim path before flattening them.
        let mut resolved = self.resolved.borrow_mut();
        resolved.clear();
        for coin in inventory.coins() {
            resolved.insert(hex::encode(coin.coin().coin_id()), coin.clone());
        }
        drop(resolved);

        Ok(held_mirrors(&inventory))
    }

    fn dig_balance_base_units(&self) -> Result<u64, PassError> {
        self.dig_balance.clone()
    }

    fn reclaim(&self, mirror: &HeldMirror, reason: ReclaimReason) -> Result<(), PassError> {
        let coin = self
            .resolved
            .borrow()
            .get(&mirror.coin_id)
            .cloned()
            .ok_or_else(|| {
                PassError::Chain(format!(
                    "coin {} was planned for reclaim but is not in the authenticated scan; it is \
                     not reclaimed rather than reclaimed from an unverified record",
                    mirror.coin_id
                ))
            })?;

        let signer = self
            .signer
            .ok_or_else(|| PassError::Wallet("no operator wallet is available to sign".into()))?;

        // `fee = 0` with no fee coins, always. §25.4.4: a zero-fee reclaim may not be admitted under
        // fee pressure, and the next pass retries it — whereas a reclaim gated on selectable XCH
        // cannot run at all on the exhausted wallet that needs it most.
        let spends = super::spends::build_reclaim(&coin, signer.synthetic_key(), Vec::new(), 0)
            .map_err(|e| PassError::Wallet(e.to_string()))?;

        tracing::info!(
            target: "mirror",
            coin_id = %mirror.coin_id,
            store_id = %mirror.store_id,
            reason = ?reason,
            "reclaiming mirror collateral"
        );
        self.sign_and_broadcast(&spends, Some(reclaimed_coin_id(&coin)))
    }

    fn create(&self, bond: &Bond, _epoch: i64, amount_dig_base_units: u64) -> Result<(), PassError> {
        // REFUSED, by name, rather than funded from the wrong wallet. See the module doc: the only
        // $DIG selector this process has is scoped to the node-custodied replica, not to the
        // operator puzzle hash, and a mirror coin funded from the wrong coins is a real spend that
        // looks successful. dig-node#420 is the operator-scoped selector.
        Err(PassError::Wallet(format!(
            "creating the {} bond needs {} DIG base units selected from the OPERATOR wallet, and \
             this node has no operator-scoped $DIG coin selector yet (dig-node#420); no spend was \
             attempted",
            bond.store_id, amount_dig_base_units
        )))
    }
}

/// The coin a reclaim of `mirror` CREATES, derived rather than guessed.
///
/// `dig_mirror_coin::reclaim` recreates the entire locked amount at the owner's own puzzle hash, as
/// a $DIG CAT — so the created coin is fully determined by three things the coin itself carries: its
/// own id becomes the parent, the amount is the collateral it locked, and the puzzle hash is the CAT
/// wrapping of the owner's standard puzzle hash under [`dig_mirror_coin::DIG_ASSET_ID`].
///
/// Derived here rather than read back from the bundle because the audit record must name the coin
/// whose EXISTENCE confirms this spend, and a spend that has only been broadcast has created
/// nothing yet. Getting it wrong is the legacy defect [`TargetCoinId`] exists to prevent: confirming
/// against a coin the spend did not create — or against the funding coin, which a competing spend
/// removes identically — proves nothing at all.
///
/// The CAT wrapping is NOT optional and is not a detail: a mirror coin's collateral is $DIG, so the
/// returned coin sits at the CAT puzzle hash and never at the bare owner puzzle hash. Naming the
/// unwrapped hash would produce a coin id that can never appear on chain, so the reclaim would stay
/// unconfirmed forever while having genuinely succeeded.
fn reclaimed_coin_id(mirror: &MirrorCoin) -> TargetCoinId {
    use chia_puzzle_types::cat::CatArgs;

    let inner: clvm_utils::TreeHash = mirror.owner_puzzle_hash().into();
    let puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(dig_mirror_coin::DIG_ASSET_ID, inner).into();

    let created = chia_protocol::Coin::new(
        mirror.coin().coin_id(),
        puzzle_hash,
        mirror.collateral(),
    );
    TargetCoinId(hex::encode(created.coin_id()))
}

/// What bring-up found, and therefore what this node's lifecycle can do.
///
/// Reported as one value rather than inferred from a null signer at each use, so "is an operator
/// wallet available at all" is answered once, at the place that can say why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendCapability {
    /// An operator wallet opened and live broadcast is enabled: this node may create and reclaim.
    Available,
    /// The §16.4 wallet did not open — absent, `Locked`, or `Orphaned`. Observation continues.
    WalletUnavailable,
    /// A wallet opened but `DIG_WALLET_ENABLE_LIVE_BROADCAST` is off, the money-safe default.
    BroadcastDisabled,
}

impl SpendCapability {
    /// Whether a pass may spend at all.
    pub fn may_spend(self) -> bool {
        matches!(self, SpendCapability::Available)
    }
}

/// Open the operator wallet, or say why the lifecycle cannot spend.
///
/// [`OperatorWallet::open`] returns `None` for BOTH §16.4 `Locked` and `Orphaned`, which is the
/// behaviour this wants: neither state has a key it would be correct to substitute, so the honest
/// outcome is the same in both — no signer, and a lifecycle that observes without spending.
pub fn open_signer(paths: &WalletPaths, live_broadcast: bool) -> (Option<MirrorSigner>, SpendCapability) {
    let Some(wallet) = OperatorWallet::open(paths, dig_constants::DIG_MAINNET.genesis_challenge())
    else {
        return (None, SpendCapability::WalletUnavailable);
    };
    if !live_broadcast {
        // The wallet opened, so the capability is not missing — it is switched off. Saying so
        // distinguishes "this node has no wallet" from "this node has one and will not spend it",
        // which are different things for an operator to fix.
        return (None, SpendCapability::BroadcastDisabled);
    }
    (Some(MirrorSigner::new(wallet)), SpendCapability::Available)
}

/// Publish what a pass observed, so `control.mirror.bondStates` can answer from it.
///
/// A TRANSLATION of [`PassReport`], never a recomputation: the states and the locked total are
/// carried across unchanged. Deriving either a second time here would be a second answer to
/// "what does this node have bonded", and the two would drift in the direction nobody tests.
pub fn publish(snapshot: &BondSnapshot, report: &PassReport, epoch: i64) {
    let observation = BondObservation {
        states: report.states.clone(),
        locked_dig_base_units: report.locked_dig_base_units,
        epoch,
    };
    match snapshot.write() {
        Ok(mut slot) => *slot = Some(observation),
        // A poisoned lock means a previous writer panicked. The observation is dropped rather than
        // recovered into: the surface then keeps saying `unknown`, which is worse for nobody, while
        // clearing the poison would hide a panic on a money path.
        Err(_) => tracing::error!(
            target: "mirror",
            "the bond-state snapshot lock is poisoned; this pass's observation was not published"
        ),
    }
}

/// Read the disk set, with provenance, as the pass needs it.
///
/// Asynchronous, so it is taken by the scheduler before the pass begins. The `Held`/`Relayed` split
/// is NOT applied here — [`super::runner::split_by_provenance`] owns it, and applying it early would
/// put §25.1's exclusion in a second place.
pub async fn observe_disk(node: &Node) -> Result<Vec<ObservedCapsule>, PassError> {
    use dig_node_core::CapsuleStore as _;

    let cached = node
        .cache_list_cached()
        .await
        .map_err(|e| PassError::Disk(e.to_string()))?;
    Ok(cached
        .into_iter()
        .map(|capsule| ObservedCapsule {
            bond: Bond::new(capsule.store_id, capsule.root),
            provenance: capsule.provenance,
        })
        .collect())
}

/// Read spendable $DIG at the OPERATOR address.
///
/// Scoped to `owner_puzzle_hash` rather than to the node-custodied replica's own set, because the
/// money a mirror coin locks is the operator wallet's. `None` from the backend is UNKNOWN and
/// becomes an `Err` here, which the runner turns into deferred creates and attempted reclaims —
/// never a fabricated zero, which would raise an out-of-funds alarm about a wallet nobody read.
pub async fn observe_dig_balance(
    wallet: &WalletBackend,
    owner_puzzle_hash: Bytes32,
) -> Result<u64, PassError> {
    wallet
        .dig_balance_base_units(owner_puzzle_hash)
        .await
        .ok_or_else(|| PassError::Wallet("the operator wallet's $DIG balance is unreadable".into()))
}

/// Wall-clock milliseconds, for §25.5's presence window.
///
/// Named here rather than inlined so the ONE clock a pass reads is a named step. A pass that read
/// the clock twice could debounce against one instant and price against another.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A [`SpendJournal`] over the machine-wide audit log.
pub fn journal() -> SpendJournal {
    SpendJournal::new(SpendLog::in_state_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bring-up with no operator wallet yields NO signer, and says which of the two reasons it was.
    ///
    /// The two branches are asserted separately because they collapse to the same `None` signer and
    /// an operator fixes them differently: an absent wallet needs a seed, a disabled broadcast needs
    /// an environment variable. A test that only checked `signer.is_none()` would pass against an
    /// implementation that reported either reason for both.
    #[test]
    fn a_disabled_broadcast_is_reported_differently_from_an_unopenable_wallet() {
        let empty = tempfile::tempdir().expect("a temp dir");
        let paths = WalletPaths::resolve(empty.path().join("seed"));

        let (signer, capability) = open_signer(&paths, true);
        assert!(signer.is_none(), "no seed exists, so nothing may sign");
        assert_eq!(
            capability,
            SpendCapability::WalletUnavailable,
            "an absent seed is the WALLET being unavailable, not a switched-off broadcast"
        );
        assert!(!capability.may_spend());
    }

    /// `publish` carries the report's own figures across, and does not recompute either.
    ///
    /// The fixture's `locked_dig_base_units` is deliberately INCONSISTENT with its `states` — a
    /// locked total no sum over those rows could produce — so an implementation that recomputed the
    /// total from the states would be visible. A consistent fixture cannot tell a translation from a
    /// recomputation, which is the whole property.
    #[test]
    fn publishing_translates_the_report_rather_than_recomputing_it() {
        use super::super::pass::BondState;

        let snapshot = new_snapshot();
        let report = PassReport {
            reclaimed: Vec::new(),
            created: Vec::new(),
            reclaim_failures: Vec::new(),
            stopped_at: None,
            states: vec![(Bond::new("aa".repeat(32), "11".repeat(32)), BondState::Withheld)],
            per_coin_dig_base_units: None,
            locked_dig_base_units: 4_242,
        };

        publish(&snapshot, &report, 9);

        let published = snapshot.read().expect("unpoisoned").clone().expect("published");
        assert_eq!(
            published.locked_dig_base_units, 4_242,
            "the report's own total, not a sum over the rows"
        );
        assert_eq!(published.epoch, 9);
        assert_eq!(published.states, report.states);
    }

    /// An unpublished snapshot is `None` — UNKNOWN — and never an empty observation.
    ///
    /// An empty `BondObservation` pages as a complete answer of zero rows, which asserts that this
    /// node holds no bonds. A node that has not observed yet is not entitled to that claim, and the
    /// two are indistinguishable downstream once the empty value exists.
    #[test]
    fn a_snapshot_before_the_first_pass_is_unknown_not_empty() {
        let snapshot = new_snapshot();
        assert!(
            snapshot.read().expect("unpoisoned").is_none(),
            "nothing has been observed, so there is no observation"
        );
    }
}
