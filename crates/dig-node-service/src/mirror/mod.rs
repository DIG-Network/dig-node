//! The mirror-coin lifecycle (dig-node#377) — presence of a `.dig` on disk, made true on chain.
//!
//! A **mirror coin** locks 20 $DIG to advertise that this node serves one `(store, root)` for one
//! epoch. This module is what keeps that advertisement honest: a capsule this node holds and is
//! willing to serve gets a coin, and a coin whose capsule is gone gets reclaimed.
//!
//! # Reclaim is loss avoidance, not cleanup
//!
//! A live coin advertising a capsule the node cannot serve is **penalised later**. So the reclaim
//! path is not tidying up after the interesting work — it is the half where money is at stake, and
//! it is held to a higher standard than the create path:
//!
//! * **Reclaims run first in every pass.** A reclaim returns collateral, which may fund the creates
//!   behind it, and a reclaim withheld because the wallet is short is the legacy defect where a
//!   wallet at zero could neither advertise nor recover what it had already locked.
//! * **Reclaims are never gated on funds.** [`plan::split_by_funds`] never sees them.
//! * **The start-up reconcile is the reliable path, not the file watcher.** A watcher's event is
//!   exactly what a crash loses; a scan at start-up re-derives the whole answer from two
//!   observations that survive anything.
//!
//! # The node signs these itself — a carve-out scoped by a separate key, not by a permission
//!
//! §908 says the node signs nothing on the user's behalf, and dig-node holds no user spend key at
//! all (the `wallet.*`/`auth.*` custody surface is retired, dig_ecosystem#1701). The carve-out is
//! therefore not a relaxation of that: mirror coins are spent by a **dedicated operating key** this
//! node derives for itself ([`key`]), which the user funds. The node signs its OWN wallet, and that
//! key controls nothing the user owns.
//!
//! Scope is then held by a type rather than a runtime check. [`spends::MirrorSpends`] has no public
//! constructor; the only producers wrap `dig_mirror_coin::create` and `::reclaim`, and the signer's
//! only entry point takes one. There is no method anywhere on this path that accepts an arbitrary
//! `CoinSpend`, so the reachable spend shapes are mirror-coin create and mirror-coin reclaim by
//! construction.
//!
//! # Accountability is what pays for it
//!
//! Because the user cannot approve each spend, they are owed a complete account of every spend made
//! without asking. The signer takes a
//! [`RecordedSpend`](crate::spend_audit::RecordedSpend) (dig-node#376), whose only source is
//! [`SpendJournal::begin`](crate::spend_audit::SpendJournal::begin) — so recording is the SHAPE of
//! the call rather than a convention a later producer can forget.
//!
//! # Nothing here re-derives the epoch or the hint
//!
//! The epoch comes from `dig_constants::mirror_epoch_at_unix_ms` and the hint from
//! `dig_mirror_coin::mirror_hint`. Both are canonical, and a locally computed version of either
//! would put coins under a value no verifier queries — collateral that is genuinely locked and
//! genuinely invisible.

pub mod key;
pub mod plan;
pub mod presence;
pub mod spends;
