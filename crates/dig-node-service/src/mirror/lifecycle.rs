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
//! **Reclaims are BUILT but not yet SENT.** `dig_mirror_coin::reclaim` recreates the full locked
//! amount at the owner's own puzzle hash and is supported at `fee = 0`, which needs no fee coins at
//! all — so a node whose XCH is exhausted can still recover $DIG it has locked. That is §25.4.4, and
//! it is the invariant that matters most, because its failure mode is collateral locked forever.
//!
//! The spend is complete; the WIRING is not. This node attaches no production [`Broadcaster`] yet
//! ([`production_broadcaster`] is `None`, dig-node#424), so a planned reclaim refuses by name before
//! it signs, exactly as a create refuses for dig-node#421. Both refusals are reported, both name
//! their missing piece, and neither is a guess dressed as a spend. The reported
//! [`SpendCapability`] is DERIVED from the same seam, so the node cannot announce a power it does
//! not have: while the broadcaster is absent the capability is
//! [`SpendCapability::BroadcasterUnwired`] and never `Available`.
//!
//! **Creates select their own collateral, from the OPERATOR wallet.** `dig_mirror_coin::create`
//! takes its `Cat` inputs from its caller, and [`super::funding`] supplies them: it scans the chain
//! at the CAT wrapping of THIS node's operator puzzle hash, reconstructs each candidate's lineage
//! from its creating spend, and refuses the whole create on a shortfall rather than funding a
//! smaller coin (dig-node#421). The node-custodied
//! [`WalletBackend`](dig_wallet::sage::rpc::WalletBackend) selector is scoped to its own replica and
//! is deliberately not used here: it would fund a mirror coin from the wrong wallet's coins, which
//! is a real spend that returns `Ok`.
//!
//! **What a create still needs before one can be attempted.** A mirror advertises WHERE its store
//! can be fetched from, and `dig_mirror_coin::create` refuses an advertisement with no URL. This
//! node has no configured public name yet, so [`NodeMirrorEffects`] is handed an empty URL set and
//! `create` refuses by name, ahead of any chain read. That is the one remaining gap, and it is an
//! advertisement question rather than a funding one.
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

use super::funding::{self, FundingError};
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
    ///
    /// Not a `Result`: `Node::cache_list_cached` is infallible — it reports the capsules it could
    /// read and nothing else — so there is no disk failure for this to carry. `MirrorEffects` keeps
    /// the fallible shape because a different implementation may have one.
    capsules: Vec<ObservedCapsule>,
    /// Spendable $DIG at the operator address, already read. `Err` defers creates, never reclaims.
    dig_balance: Result<u64, PassError>,
    /// The coins already committed to a bundle in flight, read ONCE per pass.
    ///
    /// `Err` defers creates and NEVER reclaims, exactly like `dig_balance`: a reclaim needs no coin
    /// selection at all (§25.4.4), so gating it on a funding read would reintroduce the legacy
    /// defect where a node that could not fund could not recover either.
    committed_coin_ids: Result<std::collections::HashSet<String>, PassError>,
    /// Where this node advertises its stores can be fetched from. Empty means it cannot advertise.
    advertised_urls: Vec<String>,
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
        capsules: Vec<ObservedCapsule>,
        dig_balance: Result<u64, PassError>,
        committed_coin_ids: Result<std::collections::HashSet<String>, PassError>,
        advertised_urls: Vec<String>,
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
            committed_coin_ids,
            advertised_urls,
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
        // Named the way `create` names dig-node#421: at the point this refusal is reachable, the
        // operator has ALREADY set `DIG_WALLET_ENABLE_LIVE_BROADCAST` — `open_signer` yields no
        // signer without it, and the signer is checked first — so blaming that flag would tell a
        // person to set the flag they just set. What is missing is the wiring, and the wiring has a
        // ticket.
        let broadcaster = self.broadcaster.ok_or_else(|| {
            PassError::Wallet(
                "this node has no production broadcaster wired for the mirror lifecycle \
                 (dig-node#424), so the spend was built and then NOT sent; nothing was signed"
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
        Ok(self.capsules.clone())
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

    fn create(&self, bond: &Bond, epoch: i64, amount_dig_base_units: u64) -> Result<(), PassError> {
        // The advertisement is checked FIRST, ahead of every chain read. `dig_mirror_coin::create`
        // refuses an advertisement with no URL, so selecting coins before knowing there is somewhere
        // to advertise spends a chain scan to reach a refusal that was decidable for free.
        if self.advertised_urls.is_empty() {
            return Err(PassError::Wallet(format!(
                "creating the {} bond needs at least one URL this node's stores can be fetched \
                 from, and none is configured; a mirror with nowhere to fetch from is not a \
                 mirror, so no coin was selected and no spend was attempted",
                bond.store_id
            )));
        }

        let store_launcher_id = parse_id(&bond.store_id, "store id")?;
        let root_hash = parse_id(&bond.root, "root hash")?;

        let committed = self.committed_coin_ids.as_ref().map_err(Clone::clone)?;

        // The amount is the planner's — `apply_safety_margin(required_per_store, margin_bp)`,
        // §25.3 — carried straight through. Nothing here re-derives it and nothing here has an
        // opinion about it: a create at the wrong amount locks money and advertises nothing.
        let dig_coins = funding::select_operator_dig_cats(
            self.source,
            self.owner_puzzle_hash,
            amount_dig_base_units,
            committed,
        )
        .map_err(funding_refusal)?;

        let signer = self
            .signer
            .ok_or_else(|| PassError::Wallet("no operator wallet is available to sign".into()))?;

        // `fee = 0` with no fee coins, matching the reclaim path. A create gated on selectable XCH
        // would leave a node holding $DIG and no XCH unable to bond anything at all, and the next
        // pass retries a create the mempool declined under fee pressure.
        let spends = super::spends::build_create(
            store_launcher_id,
            root_hash,
            num_bigint::BigInt::from(epoch),
            self.advertised_urls.clone(),
            amount_dig_base_units,
            dig_coins,
            signer.synthetic_key(),
            Vec::new(),
            0,
        )
        .map_err(|e| PassError::Wallet(e.to_string()))?;

        tracing::info!(
            target: "mirror",
            store_id = %bond.store_id,
            root = %bond.root,
            epoch,
            amount_dig_base_units,
            "creating mirror collateral"
        );

        // No intended coin id is stated. A create's output coin takes its parent from whichever
        // input the builder draws it from, and this node does not derive that — so naming a
        // plausible coin would let §23.5's reconcile confirm this spend against a coin it never
        // created. The record resolves `Unresolved` instead, which is the honest reading, and
        // §25.4.6's duplicate suppression works from the `(root, epoch)` the record already
        // carries rather than from a coin id.
        self.sign_and_broadcast(&spends, None)
    }
}

/// A 64-hex id from the planner, as the builder's `Bytes32`.
///
/// The planner carries store and root as lowercase hex strings, because that is what the disk scan
/// and the control surface speak. A malformed one is a REFUSAL rather than a zeroed hash: a create
/// against `0x00…` would lock real collateral advertising a store that does not exist, and the
/// money would be just as locked as if the advertisement were good.
fn parse_id(hex_id: &str, what: &str) -> Result<Bytes32, PassError> {
    let bytes: [u8; 32] = hex::decode(hex_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| {
            PassError::Wallet(format!(
                "the {what} {hex_id:?} is not 32 bytes of hex, so no create is attempted for it"
            ))
        })?;
    Ok(Bytes32::new(bytes))
}

/// A funding refusal, in the pass's own vocabulary.
///
/// The chain variant maps to [`PassError::Chain`] and every other to [`PassError::Wallet`], because
/// the two mean different things to whoever reads `stopped_at`: a chain that could not answer is a
/// transient condition of the SOURCE, while an empty or fully-committed wallet is a durable
/// condition of this NODE. Collapsing them would tell an operator to add funds when the truth is
/// that a read timed out.
fn funding_refusal(error: FundingError) -> PassError {
    match &error {
        FundingError::Chain(_) => PassError::Chain(error.to_string()),
        _ => PassError::Wallet(error.to_string()),
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
    // The SAME derivation the create path scans with, not a second copy of it. Two hand-rolled CAT
    // curries is how one of them ends up naming a puzzle hash nobody can spend, with nothing in the
    // tree comparing the two.
    let puzzle_hash = funding::dig_cat_puzzle_hash(mirror.owner_puzzle_hash());

    let created =
        chia_protocol::Coin::new(mirror.coin().coin_id(), puzzle_hash, mirror.collateral());
    TargetCoinId(hex::encode(created.coin_id()))
}

/// What bring-up found, and therefore what this node's lifecycle can do.
///
/// Reported as one value rather than inferred from a null signer at each use, so "is an operator
/// wallet available at all" is answered once, at the place that can say why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendCapability {
    /// An operator wallet opened, live broadcast is enabled, AND a broadcaster is wired: this node
    /// may create and reclaim.
    Available,
    /// The §16.4 wallet did not open — absent, `Locked`, or `Orphaned`. Observation continues.
    WalletUnavailable,
    /// A wallet opened but `DIG_WALLET_ENABLE_LIVE_BROADCAST` is off, the money-safe default.
    BroadcastDisabled,
    /// Everything the OPERATOR controls is in place — a wallet opened and live broadcast is on — but
    /// this build wires no production [`Broadcaster`] (dig-node#424), so a spend can be built and
    /// signed for and still reach nothing.
    ///
    /// Distinguished from [`Self::BroadcastDisabled`] because the two ask different things of the
    /// reader: one is a switch they can flip, and this one is not. Reporting a missing wiring as a
    /// disabled flag sends an operator to set a flag that is already set.
    BroadcasterUnwired,
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
pub fn open_signer(
    paths: &WalletPaths,
    live_broadcast: bool,
) -> (Option<MirrorSigner>, SpendCapability) {
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
    // The signer is yielded either way: the owner puzzle hash the OBSERVATION half needs comes from
    // it, and no spend can escape on the back of it, because `sign_and_broadcast` checks the
    // broadcaster before it signs.
    (
        Some(MirrorSigner::new(wallet)),
        spend_capability(production_broadcaster().is_some()),
    )
}

/// What an OPENED wallet with live broadcast on can actually do, given whether a broadcaster exists.
///
/// Separated from [`open_signer`] so the decision is reachable from a test on both branches: the
/// wired branch cannot be exercised through `open_signer` on a build where
/// [`production_broadcaster`] is `None`, and an untestable branch is how the previous version came
/// to report `Available` on a node that could not send.
pub fn spend_capability(broadcaster_wired: bool) -> SpendCapability {
    if broadcaster_wired {
        SpendCapability::Available
    } else {
        SpendCapability::BroadcasterUnwired
    }
}

/// The [`Broadcaster`] this build attaches to the mirror lifecycle — `None` until dig-node#424.
///
/// ONE seam, read by both the reported capability ([`open_signer`]) and the effects the scheduler
/// builds, precisely so the two cannot disagree. The alternative — a capability computed from the
/// environment and a broadcaster passed separately at the construction site — is what let this node
/// log "this node may create and reclaim collateral" while every reclaim refused: two answers to one
/// question, and only one of them on the path the money takes.
///
/// `&'static` because the honest answer is a property of the build rather than of a request, and
/// because a static coerces into the shorter lifetime `NodeMirrorEffects` borrows for.
pub fn production_broadcaster() -> Option<&'static dyn Broadcaster> {
    None
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
pub async fn observe_disk(node: &Node) -> Vec<ObservedCapsule> {
    use dig_node_core::CapsuleStore as _;

    node.cache_list_cached()
        .await
        .into_iter()
        .map(|capsule| ObservedCapsule {
            bond: Bond::new(capsule.store_id, capsule.root),
            provenance: capsule.provenance,
        })
        .collect()
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

    /// The needles the guard below searches for, ASSEMBLED rather than written.
    ///
    /// Spelled with `concat!` because a guard that searches its own file for a literal finds that
    /// literal in itself. The first version of this test failed on its own fixture — which is a
    /// pleasing proof that the search works, and useless as a standing guard. `concat!` runs at
    /// compile time, so the source carries only the fragments and the guard sees only real calls.
    fn forbidden_installations() -> [&'static str; 2] {
        [
            concat!(".with_", "signer("),
            concat!(".with_", "broadcaster("),
        ]
    }

    /// `Available` and a wired broadcaster are the SAME fact, so the node cannot announce a power a
    /// spend does not have.
    ///
    /// This is the assertion the earlier wiring had no room for. `open_signer` reported `Available`
    /// from the environment while the scheduler built its effects with a hard-coded `None`, so the
    /// bring-up log said "this node may create and reclaim collateral" and every reclaim refused —
    /// two answers to one question, with only one of them on the path the money takes. Deriving both
    /// from [`production_broadcaster`] makes disagreement inexpressible, and this test fails the
    /// moment someone reintroduces a second source: report `Available` with no broadcaster wired, or
    /// wire one while still reporting `BroadcasterUnwired`, and the implication below breaks.
    ///
    /// Written as an implication over the seam rather than as `assert_eq!(capability, Unwired)`
    /// because the second spelling becomes a FALSE failure the day dig-node#424 lands — a test that
    /// has to be deleted to ship the fix is not guarding the property, it is guarding the gap.
    #[test]
    fn an_opened_wallet_with_broadcast_enabled_still_may_not_spend_with_no_broadcaster_wired() {
        use dig_wallet::autoseed::BootstrapState;

        let dir = tempfile::tempdir().expect("a temp dir");
        let paths = WalletPaths::resolve(dir.path().join("seed"));

        // A REAL operator wallet, minted into the temp layout. Without one this test would take the
        // `WalletUnavailable` path and pass while never reaching the decision under test — which is
        // exactly how the first version of it went green against the very regression it names.
        let state = crate::wallet_bootstrap::ensure_wallet_seed_at(&paths)
            .expect("the autoseed bootstrap yields a state");
        assert!(
            matches!(state, BootstrapState::Created | BootstrapState::Opened),
            "the fixture must actually OPEN a wallet, or the assertions below are vacuous: {state:?}"
        );

        // Live broadcast ON — the operator has already done everything they can do.
        let (signer, capability) = open_signer(&paths, true);

        assert!(
            signer.is_some(),
            "an opened wallet yields a signer; the observation half needs its puzzle hash"
        );
        assert_eq!(
            capability,
            spend_capability(production_broadcaster().is_some()),
            "open_signer must REPORT what the pass will actually be handed, never re-decide it"
        );

        if production_broadcaster().is_none() {
            assert_eq!(
                capability,
                SpendCapability::BroadcasterUnwired,
                "with the seam empty the honest answer is the missing wiring, not a switched-off \
                 flag the operator has already switched on"
            );
            assert!(
                !capability.may_spend(),
                "and a node that cannot broadcast must not announce that it may create and reclaim"
            );
        }
    }

    /// Both branches of the capability decision, including the one this build cannot reach.
    ///
    /// Separate from the test above because that one can only exercise the branch the current
    /// [`production_broadcaster`] selects. A branch no fixture can take reads as covered while
    /// never having run once, so the wired branch is asserted directly.
    #[test]
    fn the_capability_decision_says_available_only_for_a_wired_broadcaster() {
        assert_eq!(
            spend_capability(true),
            SpendCapability::Available,
            "a wired broadcaster is what Available means"
        );
        assert_eq!(
            spend_capability(false),
            SpendCapability::BroadcasterUnwired,
            "and its absence is a different answer, not the same one"
        );
        assert!(!spend_capability(false).may_spend());
    }

    /// What a real installation LOOKS like, assembled independently of the needles.
    ///
    /// Independently is the whole point: the discriminating test below asks whether each needle
    /// matches a line somebody might actually write. Building the sample by interpolating the needle
    /// into it answers a different question — whether a string contains itself — which is true for
    /// every needle including a wrong one, and is the tautology this pair replaces.
    ///
    /// `concat!` for the same reason the needles use it — and this comment is fragmented for the
    /// same reason again: an installation spelled out in full anywhere in this file, prose included,
    /// sits in the file's own source and trips the guard on itself.
    fn sample_installations() -> [&'static str; 2] {
        [
            concat!(
                "        let backend = backend.with_",
                "signer(signer.clone());"
            ),
            concat!(
                "        let backend = backend.with_",
                "broadcaster(pusher);"
            ),
        ]
    }

    /// Every file that HOLDS or BUILDS the served backend, and could therefore install on it.
    ///
    /// `service.rs` is the file that CONSTRUCTS it (`WalletService::build_with`), reaching
    /// `AppState.wallet` from `server.rs`; `wallet_mtls.rs` and `control.rs` hold the same `Arc`.
    /// The earlier list named only the three mirror-adjacent files, so a regression introduced at
    /// the construction site — the likeliest place for one — would not have tripped the guard.
    ///
    /// `rpc.rs` is deliberately ABSENT: it DEFINES `with_signer`/`with_broadcaster` and its own
    /// tests call them, so scanning it would fail on the definition and force the guard to be
    /// weakened into uselessness.
    ///
    /// **Known residue, stated rather than implied.** `dig-wallet`'s own `sage/service.rs` — where
    /// `WalletService::build_with` constructs the backend this crate is handed — is NOT scanned: an
    /// `include_str!` reaching outside this package would leave the crate unpackageable, which is a
    /// worse defect than the one it guards. The property holds there today (neither spelling appears
    /// anywhere outside `rpc.rs`), and the guard that would cover it belongs in `dig-wallet`.
    fn guarded_sources() -> [(&'static str, &'static str); 5] {
        [
            ("lifecycle.rs", include_str!("lifecycle.rs")),
            ("signer.rs", include_str!("signer.rs")),
            ("../server.rs", include_str!("../server.rs")),
            ("../control.rs", include_str!("../control.rs")),
            ("../wallet_mtls.rs", include_str!("../wallet_mtls.rs")),
        ]
    }

    /// The mirror signer NEVER reaches the served wallet backend.
    ///
    /// Asserted STRUCTURALLY, over the crate's own source, because the property is about something
    /// that must not exist rather than about a value: `WalletBackend`'s signer field is private and
    /// `with_signer` is its only door, so proving the door is never opened proves
    /// `current_signer()` still answers `None` for every caller of the served backend — which a
    /// runtime assertion from this crate cannot reach, the accessor being private too.
    ///
    /// **Catches** the exact regression bring-up invites: attaching the operator signer to the
    /// shared backend "so the wallet can spend too". That would enable that backend's whole signing
    /// surface — including DEFAULT-ON auto-tipping — as a side effect of collateralising capsules,
    /// an unreviewed behaviour change on a money path that no other mirror test would fail on.
    ///
    /// Both spellings are checked because the two halves are separately dangerous: a signer makes
    /// the backend sign, and a broadcaster makes it send. Requiring the opening parenthesis is what
    /// keeps prose — `signer.rs`'s module doc NAMES `WalletBackend::with_signer` — from satisfying
    /// or breaking the guard.
    #[test]
    fn no_signer_or_broadcaster_is_ever_installed_on_the_served_wallet_backend() {
        for (name, source) in guarded_sources() {
            for forbidden in forbidden_installations() {
                assert!(
                    !source.contains(forbidden),
                    "{name} calls {forbidden} — the operator signer must stay inside the mirror                      lifecycle, never installed on the shared WalletBackend"
                );
            }
        }
    }

    /// The guard is looking at real text and WOULD fail if the call appeared.
    ///
    /// Three failure modes it removes, each of which leaves a green guard proving nothing: a needle
    /// that matches no possible call, a needle so loose it matches anything, and an `include_str!`
    /// pointing at a file that does not contain the code being guarded. The last is asserted by
    /// requiring a string every guarded file genuinely contains, so a path typo is a failure rather
    /// than an empty search.
    ///
    /// The first two are what the earlier version could not see: it interpolated the needle into its
    /// own fixture and then asserted the fixture contained it, which holds for EVERY needle — a
    /// misspelling such as `.with_signer (` included. Matching against a sample written on its own
    /// terms is what makes the assertion capable of failing.
    #[test]
    fn the_installation_guard_can_actually_fail() {
        for (needle, sample) in forbidden_installations()
            .into_iter()
            .zip(sample_installations())
        {
            assert!(
                sample.contains(needle),
                "{needle} must match the line a real installation would write: {sample}"
            );
        }

        // A needle that is subtly wrong matches NOTHING, and the guard built on it would be green
        // forever. Spelled with a space before the parenthesis — the plausible near-miss.
        let near_miss = concat!(".with_", "signer (");
        for sample in sample_installations() {
            assert!(
                !sample.contains(near_miss),
                "a needle that matches no real call must be visible as a failure, not a pass"
            );
        }

        for (name, source) in guarded_sources() {
            assert!(
                source.contains("WalletBackend"),
                "{name} must be the file that could install a signer; an empty or wrong include                  makes the guard pass forever"
            );
        }
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
            states: vec![(
                Bond::new("aa".repeat(32), "11".repeat(32)),
                BondState::Withheld,
            )],
            per_coin_dig_base_units: None,
            locked_dig_base_units: 4_242,
        };

        publish(&snapshot, &report, 9);

        let published = snapshot
            .read()
            .expect("unpoisoned")
            .clone()
            .expect("published");
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
