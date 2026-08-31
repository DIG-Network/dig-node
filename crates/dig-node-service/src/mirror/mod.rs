//! The mirror-coin lifecycle (dig-node#377) — presence of a `.dig` on disk, made true on chain.
//!
//! A **mirror coin** locks $DIG to advertise that this node serves one `(store, root)` for one
//! epoch. This module is what keeps that advertisement honest: a capsule this node holds and is
//! willing to serve gets a coin, and a coin whose capsule is gone gets reclaimed. `SPEC.md` §25 is
//! the normative contract; this module doc says why the shape is what it is.
//!
//! # Reclaim is loss avoidance, not cleanup
//!
//! A live coin advertising a capsule the node cannot serve is **penalised later**. So the reclaim
//! path is not tidying up after the interesting work — it is the half where money is at stake, and
//! it is held to a higher standard than the create path (§25.9):
//!
//! * **Reclaims run first in every pass.** A reclaim returns collateral, which may fund the creates
//!   behind it, and a reclaim withheld because the wallet is short is the legacy defect where a
//!   wallet at zero could neither advertise nor recover what it had already locked.
//! * **Reclaims are never gated on funds.** [`plan::split_by_funds`] never sees them.
//! * **Reclaims never wait on the collateral requirement.** A reclaim's amount is read from the coin
//!   being reclaimed, so recovering money does not depend on a census answering (§25.3).
//! * **The start-up reconcile is the reliable path, not the file watcher.** A watcher's event is
//!   exactly what a crash loses; a scan at start-up re-derives the whole answer from two
//!   observations that survive anything.
//!
//! # The node signs these itself — with its OWN operating wallet, scoped by construction
//!
//! §908 says the node signs nothing **on the user's behalf**, and it still holds no user seed and no
//! user spend key. That is untouched here. What signs a mirror spend is the node's own **operator
//! wallet** (`SPEC.md` §16.4 autoseed, sealed under the device key) — machine custody, not user
//! custody — which §23 already permits to sign certain spends automatically, and which the shipped
//! auto-tipping path (§18.23) already uses for unattended $DIG spends.
//!
//! A *separately derived* mirror key was considered and rejected. The machine identity seed is the
//! node's **network** identity (peer_id/TLS), not money custody; and a second fundable address would
//! split the user's deposit across two wallets that no balance surface can see, or else require an
//! automated wallet-to-wallet transfer — strictly *more* unattended signing than it prevents.
//!
//! Scope is therefore held by a **type**, not by a runtime check or by key hygiene.
//! [`spends::MirrorSpends`] has no public constructor; its only producers wrap
//! `dig_mirror_coin::create` and `::reclaim`, and the signer's only entry point takes one. There is
//! no method anywhere on this path that accepts an arbitrary `CoinSpend`, so the reachable spend
//! shapes are mirror-coin create and mirror-coin reclaim **by construction**. The signer instance is
//! module-private and is never installed on the general `WalletBackend`, so wiring it does not
//! change what any other surface — including default-on auto-tipping — is able to sign.
//!
//! # Accountability is what pays for it
//!
//! Because the user cannot approve each spend, they are owed a complete account of every spend made
//! without asking. So the signer takes the
//! [`SpendJournal`](crate::spend_audit::SpendJournal) (dig-node#376) and opens the record ITSELF,
//! returning the [`RecordedSpend`](crate::spend_audit::RecordedSpend) for the caller to resolve —
//! recording is the SHAPE of the call rather than a convention a later producer can forget.
//!
//! Opening it there, rather than accepting one already opened, is what makes the account TRUE
//! rather than merely present. Exactly one entry exists per signature, so N unattended spends can
//! never be accounted for as one; and the entry's amount, store and fee are derived from the spends
//! by [`spends::MirrorSpends::intent`], so no caller is in a position to state a figure the bundle
//! does not move. A record that is confidently wrong would be worse than none at all, because it is
//! the record that buys the permission to spend without asking.
//!
//! # Nothing here re-derives the epoch, the hint, or the amount
//!
//! The epoch comes from `dig_constants::mirror_epoch_at_unix_ms` and the hint from
//! `dig_mirror_coin::mirror_hint`. Both are canonical, and a locally computed version of either
//! would put coins under a value no verifier queries — collateral that is genuinely locked and
//! genuinely invisible.
//!
//! The **amount is derived per epoch** and is never a constant here: it is
//! `dig_mirror_collateral::margin::apply_safety_margin(required_per_store, margin_bp)` for the
//! current epoch, obtained through the requirement machinery `SPEC.md` §24 describes. `dig-constants`
//! carried a fixed `MIRROR_COIN_COLLATERAL_DIG = 20` until 0.13.0 removed it as a twentyfold error on
//! a real-money path — the schedule starts at **1.000 DIG** per `(store, root)`. Restating the
//! model's arithmetic is equally forbidden: `required_per_store` is the whole answer, and the formula
//! as usually written omits its floor clamp.
//!
//! All amounts in this module are **DIG base units** (1 DIG = 1_000), and every name says so. A
//! mirror amount is never "mojos" — a mojo is XCH's base unit, nine orders of magnitude away, and
//! that confusion is exactly how a money bug ships. Fees, which genuinely are XCH mojos, are named
//! `*_mojos` and come from separate coins so a fee can never shave collateral.

pub mod advertise;
pub mod bond_verify;
#[cfg(test)]
mod converge_tests;
pub mod funding;
pub mod lifecycle;
pub mod observe;
pub mod pass;
pub mod plan;
pub mod pointers;
pub mod presence;
pub(crate) mod resolve;
#[cfg(test)]
mod resolve_tests;
pub mod runner;
pub mod signer;
pub mod spends;
pub mod states;
