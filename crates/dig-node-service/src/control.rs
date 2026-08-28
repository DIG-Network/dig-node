//! The CONTROL / admin RPC surface — how a same-host controller (the DIG Browser
//! "My Node" UI, or any local tool) MANAGES the node, BESIDE the open read RPC.
//!
//! # Roles (SYSTEM.md → "Roles — serving vs consuming")
//!
//! dig-node = **serve + be-controllable**; dig-browser = **consume + control**. The
//! read methods (`dig.*`/`cache.*`) stay open to local consumers (the extension, the
//! browser's loader). The CONTROL methods here MANAGE the node — pin/unpin/list
//! hosted stores, view/clear/cap the cache, §21 sync status/trigger, get/set config,
//! and a rich node status — and are gated so a page a user merely *visits* cannot
//! drive the node.
//!
//! # Security — loopback-only + locally authorized
//!
//! Two layers, and the SECOND is the real one:
//!
//! 1. **Loopback bind (defense-in-depth, not the primary control).** By default the
//!    server binds loopback only (see [`crate::config`]); a non-loopback `DIG_NODE_HOST`
//!    is REFUSED at startup unless the operator sets `DIG_NODE_ALLOW_REMOTE=1` (#1662),
//!    so this is now an ENFORCED invariant rather than an assumption. But because an
//!    operator MAY deliberately opt into a remote bind, the control surface never relies
//!    on the bind for its protection — layer 2 does.
//! 2. **Local authorization** (the actual gate) for the mutating control namespace. A random
//!    **control token** is generated at first run into the machine-wide, identity-
//!    INDEPENDENT state dir (`<state_dir>/control-token` — [`crate::state`], #501) with
//!    a restrictive ACL. A same-host controller reads that file and presents the token
//!    on every `control.*` call — as the `X-Dig-Control-Token` request header or a
//!    `params._control_token` field. The READ methods are NOT gated; only `control.*`
//!    requires the token. The token lives in [`crate::state::state_dir`] (NOT the
//!    per-user config dir) so the daemon (which may run as a service under a different
//!    OS account) and the operator CLI resolve the SAME file.
//!
//! This is the standard "local capability file" pattern (cf. Chia's `daemon` /
//! Bitcoin's cookie auth): possession of the on-disk token = authorization, so a
//! random web page (which cannot read a local file) is rejected even though it can
//! reach loopback, while the legitimate local controller (which can) is allowed.
//!
//! The token is generated at RUNTIME from the OS CSPRNG (`getrandom` — `getrandom(2)`/
//! `/dev/urandom` on Unix, `BCryptGenRandom` on Windows, one path on every platform;
//! see [`fill_random`]) and never committed; constant-time comparison avoids a timing
//! oracle. There is NO software (non-CSPRNG) fallback: if the OS CSPRNG is unavailable
//! the node fails CLOSED — it refuses to mint a token (and the pairing methods refuse to
//! mint pairing material) rather than emit a guessable credential. So the token's
//! secrecy rests on the OS CSPRNG, NOT on an attacker's ability to estimate mint
//! time/PID/ASLR entropy.
//!
//! # What's proxied vs. owned
//!
//! Cache + sync operations proxy to digstore's `dig-node` crate (`cache_*`,
//! `clear_cache`, `set_cache_cap_bytes`, `Node::cache_fetch_and_cache` /
//! `cache_remove_cached` / `cache_list_cached`) — this service never duplicates the
//! read/cache logic. The shell owns only the small amount of state the crate does
//! not model: the **pin registry** (which stores the operator chose to host, so they
//! survive being listed even before/after caching) and the **upstream override**,
//! both persisted in this service's own keys inside the shared `config.json`.
//! `control.updater.*` (#515) proxies the DIG auto-update beacon the same way — see
//! [`crate::updater`] for what it reads directly vs. shells out to.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dig_node_control_interface::params::{
    WalletCoinByIdParams, WalletCoinSpendParams, WalletCoinsByParentParams,
    WalletReservationsReserveParams,
};
use dig_node_control_interface::ControlMethod;
use dig_node_core::seams::dig_peer::peer_network::PeerNetwork as _;
use dig_node_core::seams::dig_peer::profile_sync::{
    accept_local_body, announce_frame, LocalAcceptError, ProfileBodyStore,
};
use dig_node_core::ChainSource as _;
use dig_node_core::{CapsuleStore, Node};
use serde_json::{json, Value};

use crate::meta::ErrorCode;
use dig_wallet::sage::db::ReserveClientCoinsError;

/// The control-token file name, kept in the node's config dir next to
/// `config.json` so a same-host controller resolves it from one well-known place.
pub const CONTROL_TOKEN_FILE: &str = "control-token";

/// The request header a controller presents the control token in. Mirrors the
/// `params._control_token` alternative; either is accepted.
pub const CONTROL_TOKEN_HEADER: &str = "X-Dig-Control-Token";

/// The `params` field a controller may present the control token in, as an
/// alternative to the header (handy for JSON-RPC clients that don't set headers).
pub const CONTROL_TOKEN_PARAM: &str = "_control_token";

/// Is this method part of the gated CONTROL namespace? PURE.
///
/// Only `control.*` is gated; every read/discovery method (`dig.*`, `cache.*`,
/// `rpc.discover`) is open to local consumers.
pub fn is_control_method(method: &str) -> bool {
    method.starts_with("control.")
}

/// Is this a control method that is READ-ONLY and safe to answer WITHOUT the control token —
/// an OPEN read on the loopback read plane? PURE.
///
/// The wallet CHAIN READS (`control.wallet.balance` #1851, plus `.coins` and `.peak`
/// dig_ecosystem#2376) are reads of PUBLIC chain state (no seed, no signing key, no custody), so
/// they are exposed like the other reads rather than behind the control-token gate: a local UI can
/// poll a balance, list coins to build a spend, and bound a confirmation, without pairing.
///
/// Membership turns on WHO NAMES THE ADDRESS. `.balance`/`.coins`/`.coinById` relay a chain fact the
/// CALLER named, and `.peak`/`.syncStatus` name this node's own chain position; neither discloses
/// an association between this node and any SPECIFIC address.
///
/// `.syncStatus` is the partial exception, and it is stated rather than glossed. Since
/// dig_ecosystem#2609 it also reports `watched_addresses` — HOW MANY addresses this node follows —
/// and, through the phase, whether a wallet is ENROLLED at all. That is a count and an existence
/// bit, never an identity: no address, key, or balance is revealed.
///
/// Be precise about which field carries which disclosure, because the two are easy to swap. Both
/// `no_wallet_enrolled` and `wallet_not_unlocked` report `watched_addresses: 0` — but so can
/// `syncing`, since a refused writer watches nothing while still catching up
/// (`a_refused_writer_is_not_reported_as_nothing_to_watch`). The count therefore does NOT identify
/// that pair; the PHASE does, and the ENROLLMENT bit — not the count — separates the two from each
/// other. Reading the zero as the discriminator over-credits it. So the marginal disclosure this
/// change adds is narrow: a node watching
/// addresses was already observably wallet-bearing via a non-zero count, and what is newly visible
/// is the enrolled-but-unwatched case, previously indistinguishable from having no wallet.
///
/// It stays open because the reads it sits beside are open for the same reason — a local UI must
/// be able to say WHY it is not showing a balance without first pairing. Containment, stated
/// completely: loopback-bound, host-guarded, CORS-restricted and local-origin-checked on `/ws` —
/// **except under `DIG_NODE_ALLOW_REMOTE`**, which makes this open read network-reachable and
/// unauthenticated like every other member of this list (see the same caveat on `control.rs`'s
/// module header). It is nonetheless MORE than "no address at all", so a future field that
/// narrowed it toward a SPECIFIC address would not belong here.
///
/// Two wallet methods are deliberately NOT here. `control.wallet.arrivals` (dig_ecosystem#2548) is
/// a chain read and still gated: the caller supplies only a cursor, so the answer volunteers this
/// node's OWN watched puzzle hashes together with the receive history behind them. The chain facts
/// are public; the node-to-address association is not, and a token-less caller could replay those
/// addresses into the reads above. `control.wallet.broadcast` puts bytes on the network, so the
/// token is what stands between a local process and a broadcast — and an `UNAUTHORIZED` from it therefore
/// means exactly that, with the token as the remedy, where the same code on an OPEN read can only
/// have come from a node too old to serve it (remedy: an upgrade). Both are still routed through
/// the control dispatcher, so they stay discoverable in [`CONTROL_METHODS`] and keep their CLI
/// verbs; it is only the token requirement the server skips, and only for the set below. NO
/// mutation or custody method is ever open here.
pub fn is_open_control_read(method: &str) -> bool {
    matches!(
        method,
        "control.wallet.balance"
            | "control.wallet.coins"
            | "control.wallet.coinById"
            | "control.wallet.coinSpend"
            | "control.wallet.coinsByParent"
            | "control.wallet.peak"
            | "control.wallet.syncStatus"
            | "control.peerCounts"
    )
}

/// The canonical set of `control.*` methods the node's control plane RESOLVES — the
/// union of the methods this shell owns ([`dispatch_control`]) and the ones it delegates
/// to the embedded node's own control surface (`control.peerStatus` +
/// `control.subscribe`/`unsubscribe`/`listSubscriptions`). This is the SINGLE source of
/// truth for "what can be controlled", consumed by:
///
/// * the CLI-parity drift test (#426) — every method here MUST have a `dig-node` CLI verb
///   (see `crate::control_cli::cli_covered_control_methods`), so the CLI never silently
///   falls behind the WS control surface the extension drives;
/// * introspection — a stable list a machine can enumerate.
///
/// Keep it in lockstep with [`dispatch_control`]: a new `control.*` method added there MUST
/// be added here (and given a CLI verb), or the drift test fails.
pub const CONTROL_METHODS: &[&str] = &[
    // Owned by this shell (dispatch_control).
    "control.status",
    "control.config.get",
    "control.config.setUpstream",
    "control.log.setLevel",
    "control.cache.get",
    "control.cache.setCap",
    "control.cache.clear",
    "control.hostedStores.list",
    "control.hostedStores.pin",
    "control.hostedStores.unpin",
    "control.hostedStores.status",
    "control.capsule.fetch",
    "control.sync.status",
    "control.sync.trigger",
    "control.wallet.balance",
    "control.wallet.coins",
    "control.wallet.coinById",
    "control.wallet.coinSpend",
    "control.wallet.coinsByParent",
    "control.wallet.arrivals",
    "control.wallet.peak",
    "control.wallet.syncStatus",
    "control.wallet.watch",
    "control.wallet.unwatch",
    "control.wallet.watched",
    "control.wallet.reservations.held",
    "control.wallet.reservations.reserve",
    "control.wallet.reservations.release",
    "control.wallet.broadcast",
    "control.spends.list",
    "control.collateral.requirement",
    "control.collateral.margin.get",
    "control.collateral.margin.set",
    "control.collateral.buffer",
    "control.profile.putBody",
    "control.profile.getBody",
    "control.updater.status",
    "control.updater.setChannel",
    "control.updater.pause",
    "control.updater.resume",
    "control.updater.checkNow",
    "control.pairing.list",
    "control.pairing.approve",
    "control.pairing.revoke",
    "control.peers.ping",
    "control.peerCounts",
    "control.chiaPeers.add",
    "control.chiaPeers.list",
    "control.chiaPeers.remove",
    // Delegated to the embedded node's own control surface.
    "control.peerStatus",
    "control.peers.connect",
    "control.subscribe",
    "control.unsubscribe",
    "control.listSubscriptions",
];

/// The control methods this shell HANDLES ITSELF, in [`dispatch_control`]'s owned arms — the
/// ROUTING source of truth: [`dispatch_control`] delegates any method NOT in this set to the
/// embedded node. Adding an owned `match` arm without listing it here leaves that arm
/// unreachable (silently delegated); the lockstep test
/// (`control_methods_partition_into_owned_and_delegated`) forces this set + [`CONTROL_METHODS`]
/// to agree, so a shell-owned method can never be dispatched without also being declared.
pub const OWNED_CONTROL_METHODS: &[&str] = &[
    "control.status",
    "control.config.get",
    "control.config.setUpstream",
    "control.log.setLevel",
    "control.cache.get",
    "control.cache.setCap",
    "control.cache.clear",
    "control.hostedStores.list",
    "control.hostedStores.pin",
    "control.hostedStores.unpin",
    "control.hostedStores.status",
    "control.capsule.fetch",
    "control.sync.status",
    "control.sync.trigger",
    "control.wallet.balance",
    "control.wallet.coins",
    "control.wallet.coinById",
    "control.wallet.coinSpend",
    "control.wallet.coinsByParent",
    "control.wallet.arrivals",
    "control.wallet.peak",
    "control.wallet.syncStatus",
    "control.wallet.watch",
    "control.wallet.unwatch",
    "control.wallet.watched",
    "control.wallet.reservations.held",
    "control.wallet.reservations.reserve",
    "control.wallet.reservations.release",
    "control.wallet.broadcast",
    "control.spends.list",
    "control.collateral.requirement",
    "control.collateral.margin.get",
    "control.collateral.margin.set",
    "control.collateral.buffer",
    "control.profile.putBody",
    "control.profile.getBody",
    "control.updater.status",
    "control.updater.setChannel",
    "control.updater.pause",
    "control.updater.resume",
    "control.updater.checkNow",
    "control.pairing.list",
    "control.pairing.approve",
    "control.pairing.revoke",
    "control.peers.ping",
    "control.peerCounts",
    "control.chiaPeers.add",
    "control.chiaPeers.list",
    "control.chiaPeers.remove",
];

/// The control methods [`dispatch_control`] DELEGATES to the embedded node's own control surface
/// (`dig_node_core::handle_rpc`) — the node-internal subscription set + peer-status snapshot.
/// Together with [`OWNED_CONTROL_METHODS`] this partitions [`CONTROL_METHODS`] exactly (asserted
/// by the lockstep test): the two disjoint sets union to the full control surface.
pub const DELEGATED_CONTROL_METHODS: &[&str] = &[
    "control.peerStatus",
    "control.peers.connect",
    "control.subscribe",
    "control.unsubscribe",
    "control.listSubscriptions",
];

/// Methods this node SERVES that the published contract does not declare yet.
///
/// The list is EXPLICIT so it can only shrink. It is read by two places that must agree: the
/// conformance gate (`tests/control_contract_conformance.rs`) tolerates exactly these as known
/// drift, and [`requires_master_token`] keeps exactly these on the ordinary tier while every other
/// unpublished name fails CLOSED.
///
/// Naming them one by one is the whole point. The earlier carve-out was "anything in
/// [`CONTROL_METHODS`] the contract does not know", which widened by itself: adding a served method
/// without publishing it made it paired-reachable from that moment, and both security lockstep
/// tests stayed green because a method absent from the contract is absent from both sides of every
/// comparison they make. Granting the ordinary tier is now a reviewable one-line edit to this list
/// instead of a side effect of editing an unrelated one.
pub const KNOWN_UNPUBLISHED_CONTROL_METHODS: &[&str] = &["control.peers.ping"];

/// Does this control method require the MASTER control token, never a paired one? PURE.
///
/// The master tier is not "pairing administration": it is every method whose effect OUTLIVES the
/// token that invoked it. `pairing.revoke` is the designated remedy for a compromised paired app,
/// so a method that survives revocation has escaped that remedy and a paired token must not reach
/// it. Pairing administration is one instance of that shape; `control.chiaPeers.add`/`.remove` are
/// the others, because a trusted Chia peer is believed WITHOUT corroboration, keeps that authority
/// after the token is gone, and `revoke` touches no peer row.
///
/// # This DELEGATES to the contract, and that is the fix, not an implementation detail
///
/// The predicate is [`ControlMethod::requires_master_token`], read from
/// `dig-node-control-interface` rather than restated here. An earlier version of this function
/// listed the three pairing methods as string literals, and when the contract put `chiaPeers.*` on
/// the master tier this node kept honouring the old list — so a PAIRED token could install a peer
/// with unbounded, unrevocable authority over the wallet replica. A security predicate duplicated
/// across a repo boundary as a string match drifts silently and fails OPEN, which is why the
/// duplicate is gone instead of merely corrected. [`master_token_set_matches_the_contract`] keeps
/// it that way.
///
/// # A name this node does not serve requires the master token (fail CLOSED)
///
/// [`is_control_method`] matches on the `control.` PREFIX, so an arbitrary unrecognised name
/// reaches this gate. Such a name cannot be judged against the tier rule, so it gets the stricter
/// answer — the next method to appear is master-only by default rather than paired-reachable by
/// default.
///
/// The ONE exception is [`KNOWN_UNPUBLISHED_CONTROL_METHODS`] — names this node genuinely serves
/// that the contract has not published yet (today: one diagnostic, `control.peers.ping`). They keep
/// the ordinary tier because promoting them would break paired clients that already call them, a
/// behaviour change unrelated to the escalation this predicate closes.
///
/// The exception is bound to that explicit list rather than to "not published but served", because
/// the latter widened silently: a newly served-but-unpublished method inherited the exemption the
/// moment it was added to [`CONTROL_METHODS`], and no lockstep test could see it (a method the
/// contract does not know is absent from both sides of every comparison they make).
pub fn requires_master_token(method: &str) -> bool {
    requires_master_token_given(method, KNOWN_UNPUBLISHED_CONTROL_METHODS)
}

/// [`requires_master_token`] with the exemption list injected, so a test can state what the gate
/// does for a served-but-unpublished method that is NOT exempt.
///
/// That case has no fixture in production today — `control.peers.ping` is the only unpublished
/// method and it is exempt — and a test written against a merely-unknown name cannot distinguish
/// this rule from the one it replaces, because both answer "master" there. Injecting the list is
/// what makes the difference observable.
fn requires_master_token_given(method: &str, exempt: &[&str]) -> bool {
    match ControlMethod::from_name(method) {
        Some(published) => published.requires_master_token(),
        None => !exempt.contains(&method),
    }
}

/// The path to the control-token file: `<state_dir>/control-token`, where the state
/// dir is the machine-wide, identity-INDEPENDENT daemon state dir (#501,
/// [`crate::state::state_dir`]) — NOT the per-user config dir. Decoupling the token
/// from `config_path()` is the fix for the service-vs-user path split: the running
/// daemon and the operator CLI resolve this ONE path regardless of which OS user each
/// runs as, so the CLI reads the SAME token the service wrote.
pub fn control_token_path() -> PathBuf {
    crate::state::state_dir().join(CONTROL_TOKEN_FILE)
}

/// Load the control token, generating + persisting a fresh one if absent.
///
/// The token is 32 random bytes rendered as 64-hex. Generated at RUNTIME into the
/// machine-wide state dir ([`control_token_path`]) on first call; subsequent calls (and
/// other processes / users on the box) read the same value. The dir + file are created
/// with a RESTRICTIVE ACL (owner/SYSTEM + Administrators, the creating user; never
/// world/all-users-readable — see [`crate::state`]). Never committed.
pub fn load_or_create_token() -> std::io::Result<String> {
    load_or_create_token_at(&control_token_path())
}

/// A precise, service-aware remedy for a control-token authorization failure (#501).
///
/// The classic failure is the service-vs-user PATH/PERMISSION split: the node runs as a
/// service (Windows LocalSystem / a root daemon) and minted `control-token` in the
/// machine-wide state dir with restrictive perms, but the interactive user running
/// `dig-node pair` / a `control.*` call cannot READ it. This inspects the resolved token
/// path from the CALLER's perspective and returns the exact fix (which dir + that it
/// needs elevation or the install-user's read ACL), instead of the generic hint.
pub fn control_token_remedy() -> String {
    control_token_remedy_for(&control_token_path())
}

/// [`control_token_remedy`] for an explicit `path` (so the classification is unit-tested
/// against a temp dir without touching the real state dir / `DIG_NODE_STATE_DIR`).
///
/// Classifies by the READ RESULT, NOT by `path.exists()`: a token the SYSTEM service minted
/// under a locked-down DACL is UNreadable by the invoking (non-elevated) user, and
/// `path.exists()` then reports `false` too (the denied ACL blocks even a stat) — which used to
/// mis-render the ACL split as a bare "no control token found" (#772). The read error KIND
/// distinguishes the cases: `PermissionDenied` = present-but-locked; anything else = absent.
pub fn control_token_remedy_for(path: &Path) -> String {
    let dir = path
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    match std::fs::read_to_string(path) {
        // Blank token — treat as absent (not a state-dir mismatch).
        Ok(s) if s.trim().is_empty() => format!(
            "no control token found at {}. Start the node so it mints one (`dig-node run`, or `dig-node start` for the installed service), then retry. If the service IS already running, it is likely a STALE older build — reinstall the current dig-node (`dig-node uninstall` then an elevated `dig-node install`, then `dig-node start`) so the running service mints the token here.",
            path.display()
        ),
        // Readable and non-blank, yet the presented token was rejected — a state-dir mismatch, not an
        // ACL/mint problem.
        Ok(_) => format!(
            "the presented control token was not accepted. Ensure the node and this command resolve the SAME state dir ({dir}) — if you set DIG_NODE_STATE_DIR it must match on both the node and this command."
        ),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => format!(
            "the node's control token at {} exists but is NOT readable by your account — the node runs as a service under a different account (Windows LocalSystem / a root daemon). Re-run this command elevated (Administrator on Windows, sudo on Unix), or reinstall the current dig-node so the service grants your account read access to {} (`dig-node uninstall` then an elevated `dig-node install`, then `dig-node start`).",
            path.display(),
            dir
        ),
        // Absent (NotFound) — the node has not minted one here yet. Either it is not running,
        // or a STALE older build (installed before the machine-wide state dir) is running and
        // never mints the token at this path; reinstalling the current dig-node fixes the latter.
        Err(_) => format!(
            "no control token found at {}. Start the node so it mints one (`dig-node run`, or `dig-node start` for the installed service), then retry. If the service IS already running, it is likely a STALE older build — reinstall the current dig-node (`dig-node uninstall` then an elevated `dig-node install`, then `dig-node start`) so the running service mints the token here.",
            path.display()
        ),
    }
}

/// Read the master control token WITHOUT creating one — the OPERATOR-side load (`dig-node
/// pair` / any local control CLI, #501). It must NEVER mint a token: minting a fresh token
/// the running node does not trust is the exact original bug (the CLI wrote its own token to
/// a per-user path the service never read). On a missing/unreadable/blank token it returns a
/// rich [`std::io::Error`] carrying [`control_token_remedy`] — the precise service-vs-user
/// remedy — with the error KIND chosen so the CLI maps it to the right exit code
/// ([`crate::cli::ExitCode::from_io_error`]): `PermissionDenied` (the ACL split → "elevate")
/// when the file is present but unreadable, else `NotFound` ("start the node").
pub fn load_token_readonly() -> std::io::Result<String> {
    read_token_readonly_at(&control_token_path())
}

/// [`load_token_readonly`] for an explicit `path` — the service-mints ⇄ CLI-reads round-trip is
/// unit-tested against a temp dir with this (no `DIG_NODE_STATE_DIR` env mutation, so it is
/// race-free under parallel tests). Classifies the failure KIND by the READ error, not
/// `path.exists()`, so an ACL-denied token maps to `PermissionDenied` ("elevate") rather than a
/// misleading `NotFound` (#772).
pub fn read_token_readonly_at(path: &Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        // Present-but-blank counts as absent (never a real token). A read ERROR keeps its kind:
        // PermissionDenied ⇒ the ACL split ("elevate"); anything else ⇒ NotFound ("start the node").
        read => {
            let kind = match &read {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    std::io::ErrorKind::PermissionDenied
                }
                _ => std::io::ErrorKind::NotFound,
            };
            drop(read);
            Err(std::io::Error::new(kind, control_token_remedy_for(path)))
        }
    }
}

/// [`load_or_create_token`] for an explicit path (so tests use a temp dir and never
/// touch the real config). Reads an existing non-blank token ONLY when its file is owned by a
/// trusted principal ([`crate::state::token_file_is_trusted`], #501 residual); otherwise (or
/// when absent) generates, persists (owner-only on Unix), and returns a fresh one.
pub fn load_or_create_token_at(path: &Path) -> std::io::Result<String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            // #501 residual: TRUST a pre-existing token ONLY when its file is owned by a
            // trusted principal. An attacker who can plant a KNOWN token in the machine-wide
            // state dir — a `%PROGRAMDATA%` squat, or the narrow window during a service
            // harden — would otherwise have the daemon (LocalSystem) read + trust it, learning
            // the control token → full local node control (a local privilege escalation). A
            // foreign-owned token is deleted + regenerated, so the daemon only ever trusts a
            // token it (or a trusted principal: SYSTEM/Administrators/root) owns.
            if crate::state::token_file_is_trusted(path, crate::state::running_as_service()) {
                return Ok(t);
            }
            let _ = std::fs::remove_file(path);
        }
    }
    let token = generate_token()?;
    if let Some(dir) = path.parent() {
        // Create the state dir with a RESTRICTIVE ACL (not the world-readable default of
        // a machine-wide `%PROGRAMDATA%`) — see [`crate::state::ensure_dir_restricted`].
        crate::state::ensure_dir_restricted(dir)?;
    }
    std::fs::write(path, &token)?;
    restrict_permissions(path);
    Ok(token)
}

/// Restrict a control/auth file so it is not readable by every local user. Delegates to
/// [`crate::state::restrict_file`]: Unix `0600`; on Windows the file inherits the tight,
/// inheritable ACL of the machine-wide state dir ([`crate::state::ensure_dir_restricted`]) —
/// critical now that the file lives under `%PROGRAMDATA%`, whose default would otherwise let
/// every local user read it (a local privilege-escalation vector, #501). Best-effort (a
/// failure is ignored — loopback bind + token possession are the primary gate).
pub(crate) fn restrict_permissions(path: &Path) {
    crate::state::restrict_file(path);
}

/// Generate a fresh 64-hex control token from 32 bytes of OS-CSPRNG randomness.
/// Fails closed (propagates) if the OS CSPRNG is unavailable — the caller must refuse
/// to mint a token rather than fall back to a guessable one (see [`fill_random`]).
fn generate_token() -> std::io::Result<String> {
    random_hex(32)
}

/// `n_bytes` of OS-CSPRNG randomness rendered as lowercase hex. Used for the control
/// token (32 bytes → 64-hex) and the pairing ids/tokens (#280) — all authorization
/// material. Same CSPRNG source as [`generate_token`]; returns `Err` (never a weak
/// value) when the OS CSPRNG is unavailable so every caller can fail CLOSED.
pub(crate) fn random_hex(n_bytes: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; n_bytes];
    fill_random(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// A short numeric pairing code (6 digits, zero-padded) for the compare-codes
/// consent step (#280) — the human confirms the extension's code matches the CLI's
/// before approving. Uniformly random over `000000..=999999` from the OS CSPRNG;
/// fails closed (propagates) when the CSPRNG is unavailable.
pub(crate) fn random_pairing_code() -> std::io::Result<String> {
    let mut buf = [0u8; 4];
    fill_random(&mut buf)?;
    let n = u32::from_le_bytes(buf) % 1_000_000;
    Ok(format!("{n:06}"))
}

/// Fill `buf` with cryptographically-secure random bytes from the operating-system
/// CSPRNG on EVERY platform. `getrandom` wraps `getrandom(2)`/`/dev/urandom` on Unix
/// and `BCryptGenRandom` on Windows, so there is ONE code path everywhere.
///
/// There is deliberately NO software fallback. A weak (seed-derived) generator that is
/// exercised only when the OS source is missing is a guard nobody tests, and any
/// authorization token it minted would rest on estimating time/PID/ASLR entropy — a
/// full compromise of the control plane if guessed. Instead, when the OS CSPRNG is
/// unavailable this returns the error so the caller fails CLOSED: it refuses to mint a
/// usable token rather than emit a guessable one (§7.3; the token-mint path routes the
/// error to `resolve_state_dir_and_token`'s ephemeral in-memory fallback, and the
/// pairing methods return a control error — either way, no weak credential is issued).
fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    getrandom::getrandom(buf).map_err(|e| {
        std::io::Error::other(format!(
            "OS CSPRNG unavailable, refusing to mint authorization material: {e}"
        ))
    })
}

/// Constant-time string equality, so token verification can't be probed via a
/// timing oracle. Compares byte-by-byte over the max length, never short-circuiting.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the presented control token from a request: the `X-Dig-Control-Token`
/// header (preferred) or `params._control_token`. PURE. `header` is whatever the
/// server read from the request headers (it does header parsing; this stays I/O
/// free). Returns `None` when neither is present.
pub fn presented_token(header: Option<&str>, req: &Value) -> Option<String> {
    if let Some(h) = header {
        let t = h.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    req.get("params")
        .and_then(|p| p.get(CONTROL_TOKEN_PARAM))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Decide whether a request is AUTHORIZED to run a control method. PURE.
///
/// * Not a `control.*` method → always authorized (read methods are open).
/// * A `control.*` method → authorized only when the presented token matches the
///   expected token (constant-time).
///
/// This is the single gate the server consults; it is pure so the
/// allow/deny contract is unit-tested exhaustively without a running server.
pub fn is_authorized(method: &str, presented: Option<&str>, expected: &str) -> bool {
    if !is_control_method(method) {
        return true;
    }
    // Fail CLOSED on an unusable configured token. When the daemon could not mint a
    // token (the OS CSPRNG failed) or persist one, it falls back to an EMPTY in-memory
    // token (server.rs `resolve_state_dir_and_token`) — a node with no usable token
    // authorizes NOTHING. Guard BEFORE `ct_eq`, because `ct_eq("", "")` is `true`, so a
    // caller presenting a blank token would otherwise be accepted against a blank
    // expected — exactly the "guessable token" the empty sentinel must never be (§7.3).
    if expected.is_empty() {
        return false;
    }
    match presented {
        Some(tok) => ct_eq(tok, expected),
        None => false,
    }
}

/// A control-plane error envelope carrying a catalogued, stable code (same shape as
/// the read-plane [`crate::rpc::rpc_error`]). PURE.
pub fn control_error(id: Value, code: ErrorCode, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code.code(),
            "message": message.into(),
            "data": { "code": code.name(), "origin": code.origin() },
        },
    })
}

/// A control-plane success envelope. PURE.
pub fn control_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

// -- Pin registry (service-owned config state) -------------------------------
//
// The embedded dig-node read path models the cache as a set of capsules but has no
// concept of a "pinned" store the operator deliberately hosts. This service owns
// that small registry, persisted under its OWN key (`pinned_stores`) in the shared
// `config.json` (read-modify-write via an atomic temp+rename write), so a pin
// survives listing and an LRU eviction (the controller can re-trigger a sync for a
// pinned store).

/// The config.json key this service stores the pinned-store list under. Namespaced
/// so it never collides with dig-node's own keys (`cache_cap_bytes`, `wc_project_id`).
const PINNED_KEY: &str = "pinned_stores";

/// The config.json key for the persisted upstream override (set via
/// `control.config.setUpstream`; read by `Config::from_env` on next start).
pub const UPSTREAM_OVERRIDE_KEY: &str = "upstream_override";

/// Read the pinned-store list from the node's config.json. Each entry is a
/// canonical lowercase 64-hex store id (optionally with a pinned root, kept as a
/// `{store_id, root?}` object). Missing/blank config → empty list.
pub fn read_pins() -> Vec<Value> {
    read_pins_from(&dig_node_core::config_path())
}

/// [`read_pins`] for an explicit config path (tests).
pub fn read_pins_from(config_path: &Path) -> Vec<Value> {
    let Ok(txt) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<Value>(&txt) else {
        return Vec::new();
    };
    v.get(PINNED_KEY)
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Read the persisted upstream override from config.json, if any (blank → `None`).
pub fn read_upstream_override_from(config_path: &Path) -> Option<String> {
    let txt = std::fs::read_to_string(config_path).ok()?;
    let v: Value = serde_json::from_str(&txt).ok()?;
    v.get(UPSTREAM_OVERRIDE_KEY)
        .and_then(|u| u.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Read the persisted upstream override from the real config path.
pub fn read_upstream_override() -> Option<String> {
    read_upstream_override_from(&dig_node_core::config_path())
}

/// Read-modify-write the node's config.json, applying `mutate` to the parsed JSON
/// and writing it back atomically (temp file in the same dir + rename). Mirrors
/// dig-node's own `write_atomic` so the shared config is never observed torn. Used
/// for this service's `pinned_stores` / `upstream_override` keys ONLY — it never
/// touches dig-node's keys.
fn update_config(config_path: &Path, mutate: impl FnOnce(&mut Value)) -> std::io::Result<()> {
    if let Some(dir) = config_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut v: Value = std::fs::read_to_string(config_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| json!({}));
    mutate(&mut v);
    let bytes = serde_json::to_vec_pretty(&v).unwrap_or_default();
    write_atomic(config_path, &bytes)
}

/// Atomic write (temp in same dir + rename) — see [`update_config`]. Also used by
/// the pairing module (#280) to persist the paired-token store without a torn read.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".tmp-control-{}-{}", std::process::id(), nanos));
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Add a store (canonical 64-hex id, optional root) to the pin registry. Idempotent
/// (a store already pinned is not duplicated; pinning with a root updates the entry).
pub fn add_pin(config_path: &Path, store_id: &str, root: Option<&str>) -> std::io::Result<()> {
    let entry = match root {
        Some(r) => json!({ "store_id": store_id, "root": r }),
        None => json!({ "store_id": store_id }),
    };
    update_config(config_path, |v| {
        let arr = v
            .as_object_mut()
            .map(|o| o.entry(PINNED_KEY).or_insert_with(|| json!([])))
            .and_then(|e| e.as_array_mut());
        if let Some(arr) = arr {
            arr.retain(|e| e.get("store_id").and_then(|s| s.as_str()) != Some(store_id));
            arr.push(entry);
        }
    })
}

/// Remove a store from the pin registry. Idempotent (absent → no-op). Returns
/// whether an entry was actually removed.
pub fn remove_pin(config_path: &Path, store_id: &str) -> std::io::Result<bool> {
    let mut removed = false;
    update_config(config_path, |v| {
        if let Some(arr) = v.get_mut(PINNED_KEY).and_then(|p| p.as_array_mut()) {
            let before = arr.len();
            arr.retain(|e| e.get("store_id").and_then(|s| s.as_str()) != Some(store_id));
            removed = arr.len() != before;
        }
    })?;
    Ok(removed)
}

/// Persist the upstream override (set via `control.config.setUpstream`). A blank
/// value clears the override (falling back to env/default on next start).
pub fn set_upstream_override(config_path: &Path, upstream: &str) -> std::io::Result<()> {
    let trimmed = upstream.trim().to_string();
    update_config(config_path, |v| {
        if trimmed.is_empty() {
            if let Some(obj) = v.as_object_mut() {
                obj.remove(UPSTREAM_OVERRIDE_KEY);
            }
        } else {
            v[UPSTREAM_OVERRIDE_KEY] = json!(trimmed);
        }
    })
}

/// Is a value a canonical lowercase 64-hex string (a store id / root)? PURE.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a `storeId` or `storeId:rootHash` capsule reference into `(store_id, root?)`,
/// validating each part is 64-hex. PURE. Returns `Err(message)` on a malformed ref.
pub fn parse_store_ref(s: &str) -> Result<(String, Option<String>), String> {
    let s = s.trim();
    if let Some((store, root)) = s.split_once(':') {
        if !is_hex64(store) {
            return Err(format!("invalid store_id (want 64-hex): {store}"));
        }
        if !is_hex64(root) {
            return Err(format!("invalid root (want 64-hex): {root}"));
        }
        Ok((store.to_lowercase(), Some(root.to_lowercase())))
    } else {
        if !is_hex64(s) {
            return Err(format!("invalid store_id (want 64-hex): {s}"));
        }
        Ok((s.to_lowercase(), None))
    }
}

/// The runtime context the control dispatcher needs from the server: the embedded
/// node (for cache ops + §21 sync), the resolved config path (where pins/config
/// live), the bound addr + upstream + start instant (for status), and whether a
/// §21 identity is loaded (whole-store sync availability).
pub struct ControlCtx {
    /// The embedded dig-node, for cache list/remove/fetch + §21 sync.
    pub node: Arc<Node>,
    /// The node's config.json path (pins + upstream override live here).
    pub config_path: PathBuf,
    /// The machine-wide daemon STATE dir (#501) — where the control token +
    /// `paired-tokens.json` live (NOT the per-user config dir). The pairing-admin
    /// methods read/write the paired-token store from here.
    pub state_dir: PathBuf,
    /// The loopback `host:port` the node is bound to (status/config).
    pub addr: String,
    /// The upstream DIG RPC the node proxies/syncs to.
    pub upstream: String,
    /// The process start instant, for uptime in `control.status`.
    pub started: std::time::Instant,
    /// Whether authenticated §21 whole-store sync is available (a §21 identity is
    /// loaded). Drives `control.sync.*` and NOT_SUPPORTED.
    pub sync_available: bool,
    /// The in-memory pending-pairing set (#280), shared with the OPEN
    /// `pairing.request`/`pairing.poll` handlers so an operator-approved pairing
    /// becomes pollable by the requesting extension.
    pub pairings: Arc<std::sync::Mutex<crate::pairing::PendingPairings>>,
    /// The node-custodied wallet backend (#368), for the READ-ONLY `control.wallet.balance`
    /// chain read (#1851). A public-address balance read only — never a spend/custody path.
    pub wallet: Arc<dig_wallet::sage::rpc::WalletBackend>,
}

/// Dispatch a single authorized CONTROL method. The caller has ALREADY enforced the
/// auth gate ([`is_authorized`]); this performs the operation and returns the
/// JSON-RPC response Value. Unknown `control.*` methods → METHOD_NOT_FOUND.
pub async fn dispatch_control(ctx: &ControlCtx, id: Value, method: &str, params: &Value) -> Value {
    // Route by the SINGLE source of truth: methods this shell owns go to `dispatch_owned`;
    // everything else (the delegated set + any genuinely-unknown `control.*`) falls through to
    // the embedded node's own control surface, which resolves it or returns -32601.
    if OWNED_CONTROL_METHODS.contains(&method) {
        return dispatch_owned(ctx, id, method, params).await;
    }
    // Control methods the shell does not own are delegated to the NODE's own control surface
    // (`control.peerStatus` / `control.subscribe` / `control.unsubscribe` /
    // `control.listSubscriptions` — the node's persisted subscription set + peer-status
    // snapshot). The shell forwards them so the whole control surface is reachable through one
    // loopback endpoint. A genuinely unknown control method falls through the node too and
    // returns -32601.
    let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    // Always `Local`: reaching this point means the caller already cleared the paired-token gate
    // (enforced fail-closed in `server::rpc`, #1663) — the REAL protection on the control surface,
    // not the bind. (The bind is also loopback-only by default and a non-loopback `DIG_NODE_HOST`
    // is refused unless `DIG_NODE_ALLOW_REMOTE=1` (#1662), but the token gate is what authorizes a
    // control call regardless of where it arrives from.)
    // The control surface is the node's OWN trusted operator (token-gated, no browser / no
    // Sec-Fetch context) → first-party by definition, so its reads land exactly as before (#1956).
    dig_node_core::handle_rpc(
        &ctx.node,
        req,
        dig_node_core::download::ReadOrigin::Local,
        dig_node_core::download::RequestProvenance::FirstParty,
    )
    .await
}

/// Handle a control method OWNED by this shell (guaranteed by [`dispatch_control`] to be a member
/// of [`OWNED_CONTROL_METHODS`]). The `_` arm is [`unreachable`] BY CONSTRUCTION: it fires only if
/// [`OWNED_CONTROL_METHODS`] lists a method with no arm here (or vice-versa), i.e. the routing
/// const and the arms drifted — the lockstep test exercises this correspondence.
async fn dispatch_owned(ctx: &ControlCtx, id: Value, method: &str, params: &Value) -> Value {
    match method {
        "control.status" => control_ok(id, status(ctx).await),
        "control.config.get" => control_ok(id, config_get(ctx)),
        "control.config.setUpstream" => config_set_upstream(ctx, id, params),
        "control.log.setLevel" => log_set_level(id, params),
        "control.cache.get" => control_ok(id, cache_get()),
        "control.cache.setCap" => cache_set_cap(id, params),
        "control.cache.clear" => {
            dig_node_core::clear_cache();
            control_ok(id, json!({ "cleared": true }))
        }
        "control.hostedStores.list" => control_ok(id, hosted_list(ctx).await),
        "control.hostedStores.pin" => hosted_pin(ctx, id, params).await,
        "control.hostedStores.unpin" => hosted_unpin(ctx, id, params).await,
        "control.hostedStores.status" => hosted_status(ctx, id, params).await,
        "control.capsule.fetch" => capsule_fetch(ctx, id, params),
        "control.sync.status" => control_ok(id, sync_status(ctx).await),
        "control.sync.trigger" => sync_trigger(ctx, id, params).await,
        "control.wallet.balance" => wallet_balance(ctx, id, params).await,
        "control.wallet.coins" => wallet_coins(ctx, id, params).await,
        "control.wallet.coinById" => wallet_coin_by_id(ctx, id, params).await,
        "control.wallet.coinSpend" => wallet_coin_spend(ctx, id, params).await,
        "control.wallet.coinsByParent" => wallet_coins_by_parent(ctx, id, params).await,
        "control.wallet.arrivals" => wallet_arrivals(ctx, id, params).await,
        "control.wallet.peak" => wallet_peak(ctx, id).await,
        "control.wallet.syncStatus" => wallet_sync_status(ctx, id).await,
        "control.wallet.watch" => wallet_watch(ctx, id, params).await,
        "control.wallet.unwatch" => wallet_unwatch(ctx, id, params),
        "control.wallet.watched" => wallet_watched(ctx, id),
        "control.wallet.reservations.held" => wallet_reservations_held(ctx, id).await,
        "control.wallet.reservations.reserve" => wallet_reservations_reserve(ctx, id, params).await,
        "control.wallet.reservations.release" => wallet_reservations_release(ctx, id, params).await,
        "control.profile.putBody" => profile_put_body(ctx, id, params).await,
        "control.profile.getBody" => profile_get_body(ctx, id, params).await,
        "control.peerCounts" => peer_counts(ctx, id).await,
        // The automated-spend audit record (dig-node#385) -- a READ of this node's own spending
        // history, and the only sanctioned reader of a node-private append-only file.
        "control.spends.list" => spends_list(id, params),
        // The deterministic mirror-coin collateral model (dig_ecosystem#3173). The requirement is
        // consensus-derived and identical on every node; the margin is a LOCAL preference and the
        // two are deliberately served by different methods so neither can be mistaken for the other.
        "control.collateral.requirement" => collateral_requirement(id),
        "control.collateral.margin.get" => collateral_margin_get(id),
        "control.collateral.margin.set" => collateral_margin_set(id, params),
        "control.collateral.buffer" => collateral_buffer(id),
        "control.wallet.broadcast" => wallet_broadcast(ctx, id, params).await,
        // The DIG auto-update beacon proxy (#515) — a THIN passthrough to `dig-updater`'s
        // own status file + CLI (see `crate::updater`'s module doc for why nothing here
        // re-implements the beacon's trust/install logic).
        "control.updater.status" => crate::updater::status(id),
        "control.updater.setChannel" => crate::updater::set_channel(id, params).await,
        "control.updater.pause" => crate::updater::pause(id, params).await,
        "control.updater.resume" => crate::updater::resume(id).await,
        "control.updater.checkNow" => crate::updater::check_now(id).await,
        // Pairing administration (#280) — reached only with the MASTER token (the
        // gate blocks a paired token from these, see `requires_master_token`).
        "control.pairing.list" => crate::pairing::list(&ctx.pairings, &ctx.state_dir, id),
        "control.pairing.approve" => {
            crate::pairing::approve(&ctx.pairings, &ctx.state_dir, id, params)
        }
        "control.pairing.revoke" => crate::pairing::revoke(&ctx.state_dir, id, params),
        // The connection-ladder diagnostic (dig_ecosystem#1985) — shell-owned so it needs no
        // `dig-rpc-protocol` release; see `crate::peer_ping` for why.
        "control.peers.ping" => crate::peer_ping::ping(ctx, id, params).await,
        // The trusted-CHIA-peer surface (dig_ecosystem#2870) — a different network from
        // `control.peers.*` above, and a THIN dispatch to the wallet backend's one peer writer.
        "control.chiaPeers.add" => chia_peers_add(ctx, id, params).await,
        "control.chiaPeers.list" => chia_peers_list(ctx, id).await,
        "control.chiaPeers.remove" => chia_peers_remove(ctx, id, params).await,
        // Unreachable: `dispatch_control` only routes here for `OWNED_CONTROL_METHODS` members.
        // Reaching this arm means the routing const and these arms have drifted.
        _ => unreachable!(
            "dispatch_owned reached for non-owned control method {method:?}: \
             OWNED_CONTROL_METHODS and dispatch_owned's arms have drifted"
        ),
    }
}

/// Rich node status — the controller's at-a-glance view.
async fn status(ctx: &ControlCtx) -> Value {
    let cached = ctx.node.cache_list_cached().await;
    let hosted_store_count = distinct_store_count(&cached);
    let pins = read_pins_from(&ctx.config_path);
    json!({
        "running": true,
        "service": crate::meta::SERVICE_NAME,
        "version": crate::meta::VERSION,
        "commit": crate::meta::GIT_SHA,
        "protocol": crate::meta::PROTOCOL,
        "uptime_secs": ctx.started.elapsed().as_secs(),
        "addr": ctx.addr,
        "upstream": ctx.upstream,
        "cache": cache_get(),
        "hosted_store_count": hosted_store_count,
        "cached_capsule_count": cached.len(),
        "pinned_store_count": pins.len(),
        "sync": {
            "available": ctx.sync_available,
        },
        // The Sage-parity wallet mTLS listener (dig-node#260). Its bind is best-effort, so
        // an operator needs somewhere to SEE that it lost its port — silence was the defect.
        "wallet_mtls": crate::wallet_mtls::status_json(),
    })
}

/// Node config: bound addr/port, cache dir + shared flag, upstream, identity.
fn config_get(ctx: &ControlCtx) -> Value {
    let (dir, shared) = (crate::meta::cache_dir(), crate::meta::cache_shared());
    let port = ctx.addr.rsplit(':').next().unwrap_or("");
    json!({
        "addr": ctx.addr,
        "port": port,
        "upstream": ctx.upstream,
        "upstream_override": read_upstream_override_from(&ctx.config_path),
        "cache_dir": dir.display().to_string(),
        "cache_shared": shared,
        "config_path": ctx.config_path.display().to_string(),
        "sync_available": ctx.sync_available,
    })
}

/// Set the upstream override (persisted; effective on next node start).
fn config_set_upstream(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let Some(upstream) = params.get("upstream").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.config.setUpstream requires params.upstream (a URL string)",
        );
    };
    // #526/B2: a control character in a persisted upstream would later be baked verbatim into a
    // line of a root-owned systemd unit file at install time. `normalize_upstream` maps such a value
    // to empty (= "use the default"), so silently persisting the result would erase the operator's
    // setting instead of telling them it was rejected. Refuse it explicitly.
    if crate::config::contains_control_character(upstream) {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.config.setUpstream: params.upstream must not contain control characters",
        );
    }
    let normalized = crate::config::normalize_upstream(upstream);
    match set_upstream_override(&ctx.config_path, &normalized) {
        Ok(()) => control_ok(
            id,
            json!({
                "upstream": normalized,
                // The embedded node captured its upstream at construction, so a
                // change takes effect when the node is next started.
                "requires_restart": true,
            }),
        ),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to persist upstream override: {e}"),
        ),
    }
}

/// Cache view (cap/used/dir/shared) — reuses the dig-node crate's resolvers.
///
/// `capsule_bytes`/`response_bytes` split the same total, so `used_bytes` being large while
/// `cache.listCached` is EMPTY reads as what it is — response windows without a held capsule —
/// rather than as the two RPCs contradicting each other (#1886).
fn cache_get() -> Value {
    let usage = dig_node_core::cache_usage();
    json!({
        "cap_bytes": dig_node_core::cache_cap_bytes(),
        "used_bytes": usage.total(),
        "capsule_bytes": usage.capsule_bytes,
        "response_bytes": usage.response_bytes,
        "dir": crate::meta::cache_dir().display().to_string(),
        "shared": crate::meta::cache_shared(),
    })
}

/// Set the cache cap (bytes, floored at 64 MiB by dig-node).
/// `control.log.setLevel` (#553): live-swap the running node's `tracing` level filter via the
/// `dig-logging` reload handle (SPEC §5). The filter is a standard `EnvFilter` directive, e.g.
/// `debug` or `info,dig_node_core=debug`. This takes effect immediately WITHOUT persisting — the
/// operator persists a level across restarts with `dig-node logs level <filter>`. Fails with
/// `InvalidParams` on a missing/invalid directive and `ControlError` when logging is not installed
/// in this process (never a serving node).
fn log_set_level(id: Value, params: &Value) -> Value {
    let Some(filter) = params.get("filter").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.log.setLevel requires params.filter (an EnvFilter directive string)",
        );
    };
    match crate::logging::set_level(filter) {
        Ok(()) => control_ok(id, json!({ "filter": filter })),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to set level: {e}"),
        ),
    }
}

fn cache_set_cap(id: Value, params: &Value) -> Value {
    let Some(cap) = params.get("cap_bytes").and_then(|v| v.as_u64()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.cache.setCap requires params.cap_bytes (a number)",
        );
    };
    let floored = cap.max(64 * 1024 * 1024);
    match dig_node_core::set_cache_cap_bytes(floored) {
        Ok(()) => control_ok(id, json!({ "cap_bytes": floored })),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to set cache cap: {e}"),
        ),
    }
}

/// List hosted/pinned stores: every store the node holds (from the cache) AND every
/// pinned store, merged, with each store's cached capsules + a `pinned` flag.
async fn hosted_list(ctx: &ControlCtx) -> Value {
    let cached = ctx.node.cache_list_cached().await;
    let pins = read_pins_from(&ctx.config_path);
    let pinned_ids: std::collections::HashSet<String> = pins
        .iter()
        .filter_map(|p| {
            p.get("store_id")
                .and_then(|s| s.as_str())
                .map(str::to_string)
        })
        .collect();

    // Group cached capsules by store id.
    let mut by_store: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    for c in &cached {
        by_store.entry(c.store_id.clone()).or_default().push(json!({
            "capsule": format!("{}:{}", c.store_id, c.root),
            "root": c.root,
            "size_bytes": c.size_bytes,
            "last_used_unix_ms": c.last_used_unix_ms,
        }));
    }
    // Ensure pinned-but-not-yet-cached stores still appear.
    for id in &pinned_ids {
        by_store.entry(id.clone()).or_default();
    }

    let stores: Vec<Value> = by_store
        .into_iter()
        .map(|(store_id, capsules)| {
            let total: u64 = capsules
                .iter()
                .filter_map(|c| c.get("size_bytes").and_then(|s| s.as_u64()))
                .sum();
            json!({
                "store_id": store_id,
                "pinned": pinned_ids.contains(&store_id),
                "capsule_count": capsules.len(),
                "total_bytes": total,
                "capsules": capsules,
            })
        })
        .collect();

    json!({ "stores": stores })
}

/// Pin a store (storeId[:rootHash]): record it in the pin registry, then
/// pre-fetch the capsule into the cache via §21 sync when a concrete root is given
/// and sync is available. A pin with no root, or one made while sync is
/// unavailable, is recorded and the fetch result is reported in-band so the
/// controller can show "pinned, not yet synced".
async fn hosted_pin(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let Some(store_ref) = params.get("store").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.hostedStores.pin requires params.store (storeId or storeId:rootHash)",
        );
    };
    let (store_id, root) = match parse_store_ref(store_ref) {
        Ok(p) => p,
        Err(e) => return control_error(id, ErrorCode::InvalidParams, e),
    };
    if let Err(e) = add_pin(&ctx.config_path, &store_id, root.as_deref()) {
        return control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to record pin: {e}"),
        );
    }

    // Pre-fetch when we have a concrete root and §21 sync is available.
    let fetch = match (&root, ctx.sync_available) {
        (Some(r), true) => match ctx.node.cache_fetch_and_cache(&store_id, r).await {
            Ok((size_bytes, served_root)) => json!({
                "status": "cached",
                "size_bytes": size_bytes,
                "served_root": served_root,
            }),
            Err(e) => json!({ "status": "failed", "message": e }),
        },
        (Some(_), false) => json!({
            "status": "skipped",
            "reason": "NOT_SUPPORTED",
            "message": "no §21 identity loaded — authenticated whole-store sync unavailable",
        }),
        (None, _) => json!({
            "status": "skipped",
            "reason": "no_root",
            "message": "pinned at store level; provide storeId:rootHash to pre-fetch a capsule",
        }),
    };

    control_ok(
        id,
        json!({
            "store_id": store_id,
            "root": root,
            "pinned": true,
            "fetch": fetch,
        }),
    )
}

/// Unpin a store: remove it from the pin registry and evict its cached capsule(s).
async fn hosted_unpin(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let Some(store_ref) = params.get("store").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.hostedStores.unpin requires params.store (storeId or storeId:rootHash)",
        );
    };
    let (store_id, _root) = match parse_store_ref(store_ref) {
        Ok(p) => p,
        Err(e) => return control_error(id, ErrorCode::InvalidParams, e),
    };
    let removed = match remove_pin(&ctx.config_path, &store_id) {
        Ok(r) => r,
        Err(e) => {
            return control_error(
                id,
                ErrorCode::ControlError,
                format!("failed to remove pin: {e}"),
            )
        }
    };
    // Evict every cached capsule of this store.
    let cached = ctx.node.cache_list_cached().await;
    let mut evicted = 0u64;
    for c in cached.iter().filter(|c| c.store_id == store_id) {
        if let Ok(true) = ctx.node.cache_remove_cached(&c.store_id, &c.root).await {
            evicted += 1;
        }
    }
    control_ok(
        id,
        json!({
            "store_id": store_id,
            "unpinned": removed,
            "evicted_capsules": evicted,
        }),
    )
}

/// Per-store status: pinned flag, cached capsules, total bytes.
async fn hosted_status(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let Some(store_ref) = params.get("store").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.hostedStores.status requires params.store (storeId or storeId:rootHash)",
        );
    };
    let (store_id, _root) = match parse_store_ref(store_ref) {
        Ok(p) => p,
        Err(e) => return control_error(id, ErrorCode::InvalidParams, e),
    };
    let cached = ctx.node.cache_list_cached().await;
    let capsules: Vec<Value> = cached
        .iter()
        .filter(|c| c.store_id == store_id)
        .map(|c| {
            json!({
                "capsule": format!("{}:{}", c.store_id, c.root),
                "root": c.root,
                "size_bytes": c.size_bytes,
                "last_used_unix_ms": c.last_used_unix_ms,
            })
        })
        .collect();
    let total: u64 = capsules
        .iter()
        .filter_map(|c| c.get("size_bytes").and_then(|s| s.as_u64()))
        .sum();
    let pinned = read_pins_from(&ctx.config_path)
        .iter()
        .any(|p| p.get("store_id").and_then(|s| s.as_str()) == Some(store_id.as_str()));
    control_ok(
        id,
        json!({
            "store_id": store_id,
            "pinned": pinned,
            "capsule_count": capsules.len(),
            "total_bytes": total,
            "capsules": capsules,
        }),
    )
}

/// §21 sync status: whether authenticated whole-store sync is available, and the
/// pinned-store coverage (how many pinned stores currently have a cached capsule).
async fn sync_status(ctx: &ControlCtx) -> Value {
    let cached = ctx.node.cache_list_cached().await;
    let cached_stores: std::collections::HashSet<&str> =
        cached.iter().map(|c| c.store_id.as_str()).collect();
    let pins = read_pins_from(&ctx.config_path);
    let pinned_total = pins.len();
    let pinned_synced = pins
        .iter()
        .filter_map(|p| p.get("store_id").and_then(|s| s.as_str()))
        .filter(|s| cached_stores.contains(s))
        .count();
    json!({
        // Whole-store sync leads with the ANONYMOUS chunked `dig.getCapsule` download, so it is
        // available whether or not a §21 identity was loaded (#1886). The identity's presence is
        // reported separately rather than folded into availability, since it only decides whether
        // the authenticated §21 clone is available as a second path.
        "available": true,
        "method": "chunked-capsule-download-with-section-21-clone-fallback",
        "identity_loaded": ctx.sync_available,
        "pinned_total": pinned_total,
        "pinned_synced": pinned_synced,
        // Whole-store-by-store-id IS exposed now: `control.sync.trigger` with a store id and no
        // root resolves the store's chain-anchored tip and syncs that generation.
        "whole_store_trigger_supported": true,
    })
}

/// `control.capsule.fetch` — start a P2P whole-capsule pull, and ACK.
///
/// # This is an acknowledgement, not a completion report
///
/// A whole-`.dig` pull crosses the network and takes arbitrarily long, so blocking the control call
/// on it would hold a loopback request open for the length of a multi-hundred-megabyte transfer.
/// `"started"` therefore means STARTED — the pull is running — and never "the capsule is here".
/// Completion is observed through the cache, which is where every other reader of a landed capsule
/// looks; `control.hostedStores.status` reports it.
///
/// The three outcomes are exactly the interface's:
///
/// * `"already_cached"` — the capsule is on disk; no pull was needed and none was started.
/// * `"started"` — a background pull is running.
/// * `"unavailable"` — nothing could be started, because this build has no capsule warmer (the
///   FFI/base path has no P2P engine). Reported rather than errored because it is a true statement
///   about the capsule's reachability from this node, and the caller can act on it.
///
/// # Authorization
///
/// None is added here. This is a loopback control-plane method and the control plane already
/// authorizes every call (`ControlMethod::requires_master_token`, checked before dispatch); a second
/// story in one handler would be a second thing to keep in agreement with the first.
fn capsule_fetch(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let (store, root) = match capsule_fetch_target(params) {
        Ok(target) => target,
        Err(message) => return control_error(id, ErrorCode::InvalidParams, message),
    };

    // Checked BEFORE starting anything: a pull for a capsule already on disk would claim a warm slot
    // and report "started" for work that will immediately no-op.
    let status = if ctx.node.holds_capsule(&store, &root) {
        "already_cached"
    } else if ctx.node.start_capsule_fetch(&store, &root) {
        "started"
    } else {
        "unavailable"
    };
    control_ok(
        id,
        json!({ "store": store, "root": root, "status": status }),
    )
}

/// The `(store, root)` a `control.capsule.fetch` names, lowercased, or the refusal to answer with.
///
/// Pure, and separate from the handler, because the param contract is the half worth pinning by
/// test: the handler's other half needs a live [`Node`] and answers a filesystem question already
/// covered where that node lives.
///
/// Both ids are REQUIRED and both must be canonical 64-hex. Unlike `control.sync.trigger` there is
/// no root-less form: a capsule pull names one concrete generation, and a rootless fetch would have
/// to pick one — which is the chain's decision, made by `control.sync.trigger`, not this verb's.
fn capsule_fetch_target(params: &Value) -> Result<(String, String), &'static str> {
    let store = params.get("store").and_then(Value::as_str).unwrap_or("");
    let root = params.get("root").and_then(Value::as_str).unwrap_or("");
    if !is_hex64(store) || !is_hex64(root) {
        return Err("control.capsule.fetch requires store and root, each 64-hex");
    }
    Ok((store.to_lowercase(), root.to_lowercase()))
}

/// Trigger a whole-store sync, either for ONE capsule (`storeId:rootHash` / `store_id` + `root`)
/// or for a whole store BY STORE ID ALONE, in which case the node resolves the store's
/// chain-anchored tip and syncs that generation (#1886).
///
/// No identity gate: the chunked `dig.getCapsule` download the sync now leads with is anonymous,
/// so a node holding no §21 identity key syncs perfectly well. Rejecting the request here would
/// refuse work the node can actually do.
async fn sync_trigger(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    // Accept `store` = "storeId[:rootHash]", or explicit store_id [+ root].
    let (store_id, root) = if let Some(s) = params.get("store").and_then(|v| v.as_str()) {
        match parse_store_ref(s) {
            Ok((sid, root)) => (sid, root),
            Err(e) => return control_error(id, ErrorCode::InvalidParams, e),
        }
    } else {
        let sid = params
            .get("store_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_hex64(sid) {
            return control_error(
                id,
                ErrorCode::InvalidParams,
                "control.sync.trigger requires store_id (64-hex), optionally with a 64-hex root, \
                 or store=storeId[:rootHash]",
            );
        }
        match params.get("root").and_then(|v| v.as_str()) {
            Some(r) if !is_hex64(r) => {
                return control_error(
                    id,
                    ErrorCode::InvalidParams,
                    "control.sync.trigger root must be 64-hex when given",
                )
            }
            Some(r) => (sid.to_lowercase(), Some(r.to_lowercase())),
            None => (sid.to_lowercase(), None),
        }
    };

    // Rootless: the CHAIN picks the generation, never the serving upstream.
    let outcome = match &root {
        Some(root) => ctx.node.cache_fetch_and_cache(&store_id, root).await,
        None => ctx.node.sync_whole_store(&store_id).await,
    };

    match outcome {
        Ok((size_bytes, served_root)) => control_ok(
            id,
            json!({
                "store_id": store_id,
                "root": root.clone().unwrap_or_else(|| served_root.clone()),
                "status": "synced",
                "size_bytes": size_bytes,
                "served_root": served_root,
            }),
        ),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            match &root {
                Some(root) => format!("whole-store sync failed for {store_id}:{root}: {e}"),
                None => format!("whole-store sync failed for {store_id}: {e}"),
            },
        ),
    }
}

/// Maps the wallet backend's [`dig_wallet::sage::rpc::WalletBalanceResult`] (internally `u128`,
/// to leave headroom for summed intermediate math) onto the wire contract published by
/// `dig-node-control-interface` 0.3.0 and consumed by dig-app's `BalanceResponse`: `balance`/
/// `pending` as JSON **numbers** fitting `u64` (a single address's balance can never exceed
/// `u64::MAX` mojos, ~18.4M XCH), never JSON strings. Saturates rather than panicking on an
/// implausible overflow, since a clamped-but-alive response beats a crashed RPC call.
fn balance_wire(r: &dig_wallet::sage::rpc::WalletBalanceResult) -> Value {
    json!({
        "balance": u64::try_from(r.balance).unwrap_or(u64::MAX),
        "pending": u64::try_from(r.pending).unwrap_or(u64::MAX),
        "source": r.source,
        "synced": r.synced,
        "peak_height": r.peak_height,
    })
}

/// `control.wallet.balance` (#1851) — the READ-ONLY balance of a PUBLIC address, for XCH or
/// $DIG. An OPEN read (no token gate, [`is_open_control_read`]): it needs only an address, never
/// a seed or signing key, so it carries zero custody risk. It reuses the wallet backend's B.6
/// sync-state routing ([`dig_wallet::sage::rpc::WalletBackend::balance_for_address`]).
///
/// Params: `{ address (bech32m string), asset ("xch" | "dig") }`. Result:
/// `{ balance, pending, source, synced, peak_height }`, where `source` is `"db"` (the node's own
/// chain replica) or `"fallback"` (NOT the replica — read from a chain source), and
/// `synced`/`peak_height` describe THAT tier (#2233).
///
/// `"fallback"` names the ROUTING decision, not a party: underneath it the node tries its OWN
/// held Chia peers FIRST and reaches the public coinset oracle only when they fail. This doc
/// previously said `"fallback"` meant "a third-party coinset oracle — the address was disclosed
/// off-node", which asserted a disclosure that most `"fallback"` reads never make
/// (dig_ecosystem#2806). To see which it is, read `chia_peer_count` on
/// `control.wallet.syncStatus`: a node holding peers serves these reads from them.
///
/// A read that DID reach the oracle discloses the queried address to a third party, along with
/// the requesting IP and a timestamp. That is a real cost and it is not softened here — what
/// changed is that it is now stated of the reads it is true of, rather than of every
/// `"fallback"` answer. A node holding zero peers takes it on every one.
/// A synced empty address is a SUCCESS with a zero
/// figure; the three read-failure shapes map to DISTINCT catalogued errors (never a fabricated
/// `0`): `WALLET_NO_CHAIN_SOURCE`, `WALLET_NOT_SYNCED`, `WALLET_READ_FAILED`.
async fn wallet_balance(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let Some(address) = params.get("address").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.wallet.balance requires params.address (a bech32m address string)",
        );
    };
    let asset = match parse_asset_param("control.wallet.balance", &id, params) {
        Ok(a) => a,
        Err(e) => return e,
    };

    match ctx.wallet.balance_for_address(address, asset).await {
        Ok(r) => control_ok(id, balance_wire(&r)),
        Err(BalanceError::InvalidAddress) => control_error(
            id,
            ErrorCode::InvalidParams,
            format!("control.wallet.balance: {address:?} is not a valid bech32m address"),
        ),
        Err(BalanceError::NoChainSource) => control_error(
            id,
            ErrorCode::WalletNoChainSource,
            "no live chain source could answer this balance read",
        ),
        Err(BalanceError::NotSynced) => control_error(
            id,
            ErrorCode::WalletNotSynced,
            "the wallet is still syncing and no fallback is available to answer",
        ),
        Err(BalanceError::ReadFailed(e)) => control_error(
            id,
            ErrorCode::WalletReadFailed,
            format!("balance read failed: {e}"),
        ),
        Err(BalanceError::RateLimited) => control_error(
            id,
            ErrorCode::WalletRateLimited,
            "balance read refused: the open coinset-fallback rate limit is exhausted; back off and retry",
        ),
    }
}

use dig_wallet::sage::rpc::{BalanceAsset, BalanceError};

/// Parse `params.asset` using the PUBLISHED wire form — `"xch"`, `"dig"`, or
/// `{"cat":"<64-hex asset id>"}` (dig_ecosystem#3077).
///
/// Deserializing `dig-node-control-interface`'s own `Asset` rather than matching tokens here keeps
/// exactly one spelling of the contract in the ecosystem: a shape the crate accepts is a shape the
/// node accepts, automatically.
///
/// # An absent asset means XCH; an UNPARSEABLE one is an error
///
/// Those two are deliberately different. Omitting the field is a caller asking for the default
/// asset, which the contract has always said is native XCH. A field that is present and does not
/// name an asset is a caller asking for something this node cannot scope a read to — and defaulting
/// THAT to XCH is how a mistyped asset id becomes a confident balance for the wrong token.
fn parse_asset_param(
    method: &str,
    id: &Value,
    params: &Value,
) -> std::result::Result<BalanceAsset, Value> {
    let Some(raw) = params.get("asset") else {
        return Ok(BalanceAsset::Xch);
    };
    serde_json::from_value::<ControlAsset>(raw.clone())
        .map(BalanceAsset::from)
        .map_err(|e| {
            control_error(
                id.clone(),
                ErrorCode::InvalidParams,
                format!(
                    "{method} asset must be \"xch\", \"dig\", or {{\"cat\":\"<64-hex>\"}}: {e}"
                ),
            )
        })
}

use dig_node_control_interface::params::Asset as ControlAsset;

/// The address + asset params shared by `control.wallet.balance` and `control.wallet.coins` — a
/// balance is a coins read reduced to a sum, so the two take the SAME shape (and dig-app's frozen
/// `CoinsRequest` doubles as its balance request for the same reason).
///
/// Returns the parsed pair, or the JSON-RPC error response to send back verbatim.
fn wallet_address_params(
    method: &str,
    id: &Value,
    params: &Value,
) -> std::result::Result<(String, dig_wallet::sage::rpc::BalanceAsset), Value> {
    let Some(address) = params.get("address").and_then(|v| v.as_str()) else {
        return Err(control_error(
            id.clone(),
            ErrorCode::InvalidParams,
            format!("{method} requires params.address (a bech32m address string)"),
        ));
    };
    let asset = parse_asset_param(method, id, params)?;
    Ok((address.to_string(), asset))
}

/// Parse + validate `params.coin_id` for `control.wallet.coinById`, yielding the canonical bare
/// lowercase 64-hex form.
///
/// # Refused BEFORE any network call
///
/// This runs first in [`wallet_coin_by_id`], ahead of the liveness check, the rate limiter and the
/// chain read. `control.wallet.coinById` is an OPEN, token-less method whose argument is forwarded
/// to a third-party oracle, so accepting an unvalidated string would let any local process push
/// arbitrary content at that oracle through this node.
///
/// # The RULE is the published contract's, not this node's
///
/// The well-formedness rule itself is [`WalletCoinByIdParams::validated`], consumed from
/// `dig-node-control-interface` rather than restated here. A second copy of a published rule agrees
/// until it does not, and the divergence would surface as a mint that never confirms — while the
/// conformance suite, which pins method names and auth posture only, stayed green throughout. This
/// function contributes only what the contract type cannot: reading the field off an untyped
/// JSON-RPC `params` value, and shaping the refusal as this node's catalogued error.
///
/// Uppercase is therefore REFUSED rather than normalized, because the contract accepts exactly one
/// spelling and strips only the `0x` prefix. Lowercasing here would make this node accept ids a
/// conforming implementation rejects.
fn wallet_coin_id_param(id: &Value, params: &Value) -> std::result::Result<String, Value> {
    coin_id_field(id, "control.wallet.coinById", "coin_id", params, |raw| {
        WalletCoinByIdParams { coin_id: raw }
            .validated()
            .ok()
            .map(|p| p.coin_id)
    })
}

/// Parse + validate `params.coin_id` for `control.wallet.coinSpend` (dig_ecosystem#2572).
///
/// Same field, same rule, same refuse-before-the-network ordering as
/// [`wallet_coin_id_param`] — but the rule is taken from the contract's OWN
/// [`WalletCoinSpendParams`] rather than reusing `coinById`'s type. The two are identical today and
/// the contract is free to let them diverge; a node that borrowed one method's validator for
/// another would silently stop conforming the day they did.
fn wallet_coin_spend_param(id: &Value, params: &Value) -> std::result::Result<String, Value> {
    coin_id_field(id, "control.wallet.coinSpend", "coin_id", params, |raw| {
        WalletCoinSpendParams { coin_id: raw }
            .validated()
            .ok()
            .map(|p| p.coin_id)
    })
}

/// Parse + validate the whole `control.wallet.coinsByParent` request: the parent id, the optional
/// resume cursor, and the optional page size (dig_ecosystem#2572).
///
/// # Every rule comes from the contract's own [`WalletCoinsByParentParams::validated`]
///
/// Including the ones a node would be tempted to soften. A `limit` of zero or above the maximum is
/// REFUSED, never clamped, because this read's page boundary is what the caller resumes from: a
/// silently shrunk page hands back a cursor for a position the caller never asked about, and a
/// caller trusting its own number mis-sizes every request after it. `after_coin_id` is held to the
/// same hex rule as the parent, so a malformed cursor is a refusal rather than a page that silently
/// starts from the beginning.
///
/// # Refused BEFORE any network call
///
/// Same ordering, and same reason, as [`wallet_coin_id_param`]: this is an OPEN, token-less method
/// forwarding caller-supplied strings to a third-party oracle.
///
/// The three fields are read separately from the untyped `params` and then validated TOGETHER, so a
/// request that is wrong in two ways is still refused, and refused before anything is dialed.
fn wallet_coins_by_parent_params(
    id: &Value,
    params: &Value,
) -> std::result::Result<WalletCoinsByParentParams, Value> {
    const METHOD: &str = "control.wallet.coinsByParent";
    let invalid = |detail: String| {
        Err(control_error(
            id.clone(),
            ErrorCode::InvalidParams,
            format!("{METHOD}: {detail}"),
        ))
    };
    let Some(parent_coin_id) = params.get("parent_coin_id").and_then(|v| v.as_str()) else {
        return invalid(
            "params.parent_coin_id must be a 64-character lowercase-hex coin id string".to_string(),
        );
    };
    // A present-but-wrong-typed field is refused rather than silently ignored: a caller that sent
    // `limit: "50"` asked for a page size, and serving it the default while reporting success would
    // make the page boundary — the thing it resumes from — different from the one it believes in.
    let after_coin_id = match params.get("after_coin_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => {
            return invalid(format!(
                "params.after_coin_id must be a coin id string or omitted, got {other}"
            ))
        }
    };
    let limit = match params.get("limit") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64().and_then(|n| u32::try_from(n).ok()) {
            Some(n) => Some(n),
            None => {
                return invalid(format!(
                    "params.limit must be a positive whole number or omitted, got {v}"
                ))
            }
        },
    };
    WalletCoinsByParentParams {
        parent_coin_id: parent_coin_id.to_string(),
        after_coin_id,
        limit,
    }
    .validated()
    .or_else(|e| invalid(e.message))
}

/// Read one coin-id field off untyped JSON-RPC `params` and hand it to the CONTRACT's validator,
/// shaping any refusal as this node's catalogued `INVALID_PARAMS`.
///
/// The three by-coin reads enforce the same well-formedness rule under two field names, and each
/// supplies its own `validate` — the published rule for THAT method — so this function never
/// restates the rule and cannot drift from it. What it contributes is the part the contract types
/// cannot: pulling a named string out of a `Value`, and the error prose.
fn coin_id_field(
    id: &Value,
    method: &str,
    field: &str,
    params: &Value,
    validate: impl FnOnce(String) -> Option<String>,
) -> std::result::Result<String, Value> {
    let invalid = |detail: &str| {
        Err(control_error(
            id.clone(),
            ErrorCode::InvalidParams,
            format!("{method} requires params.{field}, {detail}"),
        ))
    };
    let Some(raw) = params.get(field).and_then(|v| v.as_str()) else {
        return invalid("a 64-character lowercase-hex coin id string");
    };
    match validate(raw.to_string()) {
        Some(valid) => Ok(valid),
        None => {
            invalid("a 64-character LOWERCASE-hex coin id (an optional `0x` prefix is allowed)")
        }
    }
}

/// Map a wallet READ failure onto its catalogued control error. Shared by the balance and coin
/// reads so the two can never classify the same failure differently.
fn wallet_read_error(method: &str, id: Value, address: &str, e: BalanceError) -> Value {
    match e {
        BalanceError::InvalidAddress => control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{method}: {address:?} is not a valid bech32m address"),
        ),
        BalanceError::NoChainSource => control_error(
            id,
            ErrorCode::WalletNoChainSource,
            "no live chain source could answer this read",
        ),
        BalanceError::NotSynced => control_error(
            id,
            ErrorCode::WalletNotSynced,
            "the wallet is still syncing and no fallback is available to answer",
        ),
        BalanceError::ReadFailed(e) => control_error(
            id,
            ErrorCode::WalletReadFailed,
            format!("chain read failed: {e}"),
        ),
        BalanceError::RateLimited => control_error(
            id,
            ErrorCode::WalletRateLimited,
            "read refused: the open coinset-fallback rate limit is exhausted; back off and retry",
        ),
    }
}

/// `control.wallet.coins` (dig_ecosystem#2376) — the UNSPENT coins at a PUBLIC address, for XCH or
/// $DIG. An OPEN read for the same reason as the balance: it needs only an address.
///
/// Params: `{ address, asset }` (identical to the balance read). Result:
/// `{ coins:[{coin_id, asset, amount, parent_coin_info, puzzle_hash, created_height, spent_height}],
/// source, synced, peak_height }`.
///
/// `coins: []` means a chain was consulted and the address holds nothing. Every way of failing to
/// consult one is a DISTINCT catalogued error, never an empty list — an empty list would tell a
/// holder of funds that they hold none, and a spend built on that refuses with an untrue shortfall.
async fn wallet_coins(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.wallet.coins";
    let (address, asset) = match wallet_address_params(METHOD, &id, params) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    match ctx.wallet.coins_for_address(&address, asset).await {
        Ok(r) => control_ok(id, coins_wire(&r, asset)),
        Err(e) => wallet_read_error(METHOD, id, &address, e),
    }
}

/// `control.wallet.coinById` (dig_ecosystem#2392) — ONE coin by coin id, spent or unspent.
///
/// The read a caller polling a spend needs: "did the coin I created appear, and is the coin I
/// funded it with gone?" Neither can be asked by address. An OPEN read for the same reason as the
/// balance and `.coins`: its argument is a public chain identifier and nothing else.
///
/// Params: `{ coin_id }`. Result: `{ coin: <record|null>, source, synced, peak_height }`.
///
/// `coin: null` means a chain source ANSWERED and reported no such coin. Every way of failing to
/// get an answer at all is a distinct catalogued error carrying NO `result` member at all — so a
/// `null` coin is unambiguous by construction rather than by convention.
///
/// `null` is NOT proof the chain has no such coin: it can come from ONE peer's empty coin-state
/// list (dig_ecosystem#2456, one crate down), and such a peer may be a block behind, mid-reorg,
/// pruning or hostile. A caller polling a mint reads `null` as "not seen yet" and keeps polling.
/// A non-null coin IS bound to the id asked for — a coin id is self-certifying and the wallet
/// rejects a substituted record.
async fn wallet_coin_by_id(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let coin_id = match wallet_coin_id_param(&id, params) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    match ctx.wallet.coin_by_id(&coin_id).await {
        Ok(r) => control_ok(id, coin_by_id_wire(&r)),
        Err(e) => wallet_read_error("control.wallet.coinById", id, &coin_id, e),
    }
}

/// `control.wallet.coinSpend` (dig_ecosystem#2572) — the SPEND that spent ONE coin.
///
/// The read that turns "my coin is gone" into "here is what it became": a coin record carries a
/// puzzle HASH, and only a spend carries the puzzle REVEAL and the solution. Following a DID
/// singleton forward — the walk a dig-profile resolution performs — is this method plus
/// [`wallet_coins_by_parent`], composed by the caller. An OPEN read for the same reason as
/// `coinById`: its argument is a public chain identifier and nothing else.
///
/// Params: `{ coin_id }`. Result: `{ spend: <spend|null>, source, synced, peak_height }`.
///
/// `spend: null` means a chain source ANSWERED and holds no spend of that coin — it is unspent, or
/// unknown. Telling those two apart is `control.wallet.coinById`'s job, not this one's. Every way of
/// failing to get an answer at all is a distinct catalogued error carrying no `result` member, so a
/// `null` spend is unambiguous by construction: a caller walking a lineage may read `null` as "this
/// is the tip I can see" without also having to rule out an outage.
///
/// A returned spend's puzzle reveal has been verified to tree-hash to the spent coin's own puzzle
/// hash, and its coin carries a real `spent_height` — the node refuses rather than emitting either
/// unchecked.
async fn wallet_coin_spend(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.wallet.coinSpend";
    let coin_id = match wallet_coin_spend_param(&id, params) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    match ctx.wallet.coin_spend(&coin_id).await {
        Ok(r) => control_ok(id, coin_spend_wire(&r)),
        Err(e) => wallet_read_error(METHOD, id, &coin_id, e),
    }
}

/// `control.wallet.coinsByParent` (dig_ecosystem#2572) — the DIRECT children a coin's spend created.
///
/// ONE hop. The node never recurses: a transitive walk over a caller-supplied id is unbounded work
/// on a token-less endpoint, and a partial walk served as a complete one is a lineage with a silent
/// hole in it. A caller wanting a lineage composes hops itself.
///
/// Params: `{ parent_coin_id, after_coin_id?, limit? }`. Result:
/// `{ coins: [...], complete, cursor, source, synced, peak_height }`.
///
/// `coins: []` means a chain source ANSWERED and that parent created no children it knows of —
/// typically because the parent is unspent. Every way of failing to consult a chain is a catalogued
/// error, never an empty list, because an empty list reads as *that spend created nothing* and ends
/// a lineage walk early.
///
/// The answer is ONE PAGE, ascending by `coin_id`. `complete` states whether it is the whole child
/// set and is never left to be inferred from the page's length; `cursor` is the last child handed
/// over, which the caller passes back as `after_coin_id`.
async fn wallet_coins_by_parent(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.wallet.coinsByParent";
    let request = match wallet_coins_by_parent_params(&id, params) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    // `effective_limit` resolves an omitted page size using the CONTRACT's default, so a node and a
    // client can never disagree about where an unspecified page ends.
    let limit = request.effective_limit();
    match ctx
        .wallet
        .coins_by_parent(
            &request.parent_coin_id,
            request.after_coin_id.as_deref(),
            limit,
        )
        .await
    {
        Ok(r) => control_ok(id, coins_by_parent_wire(&r)),
        Err(e) => wallet_read_error(METHOD, id, &request.parent_coin_id, e),
    }
}

/// The default and maximum page size for `control.wallet.arrivals`.
///
/// Bounded because the page size is caller-chosen on an OPEN, token-less method: an unbounded
/// `limit` lets any local process ask this node to materialize the whole ledger per call.
const ARRIVALS_DEFAULT_LIMIT: i64 = 50;
const ARRIVALS_MAX_LIMIT: i64 = 500;

/// `control.wallet.arrivals` (dig_ecosystem#2548) — incoming funds CONFIRMED since a cursor.
///
/// The answer to "did the user just get paid?", which no other method can give: `.balance` reports
/// a total that the user's own change also moves, and `.coins` cannot say which of its coins are
/// new. Each row is a coin the node determined ARRIVED — confirmed on chain, above the wallet's
/// arrival baseline, not previously reported, and not created by spending one of the wallet's own
/// coins. The determination lives in [`dig_wallet::sage::arrivals`]; this method only pages it out.
///
/// Params: `{ after_seq?: integer (default 0), limit?: integer (default 50, max 500) }`.
/// Result: `{ arrivals: [{seq, coin_id, puzzle_hash, amount, asset_id, confirmed_height}], cursor,
/// latest }`.
///
/// # A pull, deliberately
///
/// The control envelope is strictly request→response — it has no server-initiated frame — so this
/// is a cursor a client polls rather than a stream. A client resumes from `cursor`, the last `seq`
/// it was actually handed; `latest` is the ledger's newest position and exists only so a first-run
/// client can start from NOW instead of replaying the whole ledger (see [`arrivals_wire`] for why
/// the two must not be collapsed). Positions are `AUTOINCREMENT` and persisted, so they survive a
/// restart of either side and a reorg cannot make an old cursor point at a different arrival.
///
/// # Every row is CONFIRMED, and `arrivals: []` is an answer
///
/// A mempool sighting is structurally absent: the stored confirmation height is `NOT NULL` and a
/// coin without one is never written. An empty list means the node consulted its own replica and
/// nothing has arrived since the cursor — it is NOT a claim that the wallet is up to date. A caller
/// that needs to know whether the replica is current asks `control.wallet.syncStatus`; a node that
/// has never completed a catch-up has no arrival baseline and reports an empty list forever, which
/// is the honest answer to "what arrived?" from a wallet that cannot tell history from news.
///
/// # TOKEN-GATED, unlike the other wallet reads
///
/// It touches only this node's LOCAL replica and has no oracle path, so polling it discloses
/// nothing to a THIRD party — but it discloses plenty to the CALLER. The other reads answer about
/// an address the caller already named; this one takes a cursor and answers with the node's OWN
/// watched puzzle hashes and the receive history behind them. The chain facts are public; the
/// association between this node and those addresses is not, and a token-less caller could replay
/// the disclosed addresses into `.balance` and `.coins`. So an `UNAUTHORIZED` here means exactly
/// what it says, and the remedy is the token — not an upgrade ([`is_open_control_read`]).
async fn wallet_arrivals(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.wallet.arrivals";
    let after_seq = params
        .get("after_seq")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if after_seq < 0 {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{METHOD} after_seq must be a non-negative integer"),
        );
    }
    match ctx
        .wallet
        .wallet_arrivals(after_seq, arrivals_limit(params))
        .await
    {
        Ok((page, latest)) => control_ok(id, arrivals_wire(after_seq, &page, latest)),
        // Only the local wallet DB can fail here — there is no chain call to blame.
        Err(e) => control_error(
            id,
            ErrorCode::WalletReadFailed,
            format!("{METHOD}: reading the local arrival ledger failed: {e}"),
        ),
    }
}

/// The page size `control.wallet.arrivals` will actually use. PURE.
///
/// Clamped at BOTH ends rather than only the top: a zero or negative `limit` reaching SQLite's
/// `LIMIT` would mean "no rows" or "no bound" depending on the value, and neither is what a caller
/// asking for a page meant.
fn arrivals_limit(params: &Value) -> i64 {
    params
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(ARRIVALS_DEFAULT_LIMIT)
        .clamp(1, ARRIVALS_MAX_LIMIT)
}

/// Map recorded arrivals onto the wire.
///
/// `amount` is a STRING because the ledger stores the full `u64` range and JSON numbers do not
/// carry it losslessly; `asset_id` is `null` for native XCH and the CAT's hex TAIL otherwise —
/// never a ticker, because naming an asset this node did not attribute would be a claim it cannot
/// support.
///
/// # `cursor` is where the CLIENT got to, not where the LEDGER got to
///
/// It is the last `seq` actually returned, falling back to the caller's own `after_seq` on an empty
/// page — deliberately NOT `latest`. `latest` is read after the page, so an arrival recorded in
/// between would sit above the page and below `latest`, and a client resuming from `latest` would
/// step straight over it. Silently losing one notification is the failure this method exists to
/// prevent, so the resume value can only ever be a row the client was actually handed.
///
/// `latest` is reported alongside for the one question `cursor` cannot answer: a first-run client
/// reads it and passes it back as `after_seq` to start from NOW, instead of replaying the whole
/// ledger as a burst of notifications.
fn arrivals_wire(
    after_seq: i64,
    arrivals: &[dig_wallet::sage::arrivals::Arrival],
    latest: i64,
) -> Value {
    let cursor = arrivals.last().map_or(after_seq, |a| a.seq);
    json!({
        "arrivals": arrivals.iter().map(|a| json!({
            "seq": a.seq,
            "coin_id": a.coin_id,
            "puzzle_hash": a.puzzle_hash,
            "amount": a.amount,
            "asset_id": a.asset_id,
            "confirmed_height": a.confirmed_height,
        })).collect::<Vec<_>>(),
        "cursor": cursor,
        "latest": latest,
    })
}

/// `control.wallet.peak` (dig_ecosystem#2376) — the node's current chain peak height.
///
/// Its own method rather than a field on a balance: a balance reports `peak_height: null` on every
/// fallback-tier answer by design (#2233), so a caller bounding a claimed confirmation could not get
/// one from the very node that most needs to answer. `peak_height: null` here means UNKNOWN — never
/// height zero, which every block is trivially above.
async fn wallet_peak(ctx: &ControlCtx, id: Value) -> Value {
    match ctx.wallet.chain_peak().await {
        Ok(peak) => control_ok(
            id,
            json!({ "peak_height": peak.peak_height, "synced": peak.synced }),
        ),
        Err(e) => wallet_read_error("control.wallet.peak", id, "", e),
    }
}

/// `control.wallet.syncStatus` (dig_ecosystem#2501) — is the wallet's chain replica being kept
/// current, how far has it got, and how many Chia peers is it using?
///
/// # `synced` means CAUGHT UP **AND** CONNECTED
///
/// Not "once caught up". A wallet that finished its catch-up yesterday and has been offline since
/// reports `syncing`, because it is trying to be current and is not. That makes this phase
/// strictly stronger than `control.wallet.peak`'s `synced` flag, which only reflects the
/// completed-catch-up bit. It is still NOT a freshness guarantee — a live connection to a stalled
/// peer satisfies it — so a consumer needing freshness compares `peak_height` against something.
///
/// # The height is the REPLICA's, never an oracle's
///
/// `peak_height` is read straight from the wallet DB's `sync_state`. It must never come from
/// [`dig_wallet::sage::rpc::WalletBackend::chain_peak`], which falls back to the coinset oracle:
/// that would answer *how far has this replica got?* with a number the replica never reached, and
/// would route an unauthenticated loopback read into outbound requests — the egress-amplification
/// shape `WALLET_RATE_LIMITED` exists to bound (dig_ecosystem#1957), which also discloses
/// `{IP, timestamp, coin id}` to the third party. The backend accessor used here has no oracle
/// path at all.
///
/// `{phase: not_started, peak_height: <n>}` is legitimate, not a contradiction: it is the RESTART
/// state — a node with a height recorded by a previous run that has not yet begun syncing.
///
/// # The two nothing-to-watch phases are NOT kinds of `syncing` (dig_ecosystem#2609)
///
/// The five tokens are `not_started`, `syncing`, `synced`, `no_wallet_enrolled` and
/// `wallet_not_unlocked`, and they are the set published by
/// `dig_node_control_interface::results::WalletSyncPhase` — a node MUST NOT emit anything outside
/// it. `no_wallet_enrolled` is the DEFAULT-INSTALL state: a node with no wallet enrolled has zero puzzle hashes, and a
/// catch-up over an empty set is refused rather than performed, so `initial_sync_complete` never
/// latches — while the replica's peak advances with the chain the whole time. Reporting that as
/// `syncing` told every consumer the node was behind when it was at the tip, and dig-app withheld
/// the balance forever behind "your node is still catching up with the blockchain".
///
/// A consumer must render it as ITS OWN sentence — the node is current, and there is simply
/// nothing wallet-scoped to sync — never as chain lag and never as a balance it is still waiting
/// for. It is deliberately not folded into `synced`, which additionally licenses serving
/// wallet-scoped reads from the local replica.
///
/// # `wallet_not_unlocked` looks identical from inside the sync loop and means the OPPOSITE
///
/// An empty address set is produced by two states that are indistinguishable from the subscription
/// alone: no wallet exists (above — nothing to do), and a wallet EXISTS whose addresses this node
/// cannot derive (something to do that is not being done). The node separates them by asking
/// custody's manifest whether any wallet is enrolled, because the derivable key set answers the
/// wrong question — it is empty for a LOCKED wallet, which is the common state after every
/// restart, and also for an adopted legacy seed or a manifest predating the stored-key field.
///
/// Under `wallet_not_unlocked` the user's coins are NOT being followed. A consumer MUST NOT render
/// it as synced, settled, or up to date, and MUST NOT present a balance read under it as complete.
/// Collapsing the two would report an unwatched wallet as an all-clear — the same class of
/// falsehood this method was fixed to remove, one conflation further along.
///
/// # The reason field
///
/// `watched_addresses` reports WHY: `0` is a measured empty address set, a positive count is a real
/// subscription, and `null` means no attached session has resolved a set yet (a peer is
/// mid-corroboration, or none is attached). A consumer must not read `null` as `0`.
///
/// # Two peer counts, because the node holds two different sets (dig_ecosystem#2806)
///
/// `chia_peer_count` is the headline light-client number: Chia full nodes this node HOLDS, whose
/// pool serves its chain reads. `subscription_peer_count` is the replica's subscription session,
/// at most one by design. Until #2806 this method reported the SECOND number under the FIRST
/// name, so a node holding five peers and serving every read from them announced
/// `chia_peer_count: 1` — a figure that was neither the peers serving reads nor the total, and
/// that made the node look like a one-peer client. They are separate sets with separate
/// lifetimes: a consumer MUST NOT add them.
///
/// `chia_peer_peak_height` is the peak those held peers ANNOUNCED to this node. It is the one
/// height on this payload that evidences a live light client — `peak_height` is the replica's own
/// progress, and a peak fetched from a public oracle would prove nothing about the node's peers.
/// `null` means no peer has announced one yet, never height zero.
///
/// # The token set is the CONTRACT's, not this file's
///
/// The five tokens are exactly `WalletSyncPhase::ALL` in `dig-node-control-interface`, and a token
/// this node emits that the contract does not declare fails a consumer's ENTIRE response parse
/// rather than one field — the #2609 regression. A new phase is published in that crate FIRST and
/// emitted here second; `every_phase_the_node_can_emit_is_declared_by_the_published_contract`
/// enforces the ordering.
async fn wallet_sync_status(ctx: &ControlCtx, id: Value) -> Value {
    match ctx.wallet.wallet_sync_status().await {
        Ok(s) => control_ok(
            id,
            json!({
                "phase": s.phase,
                "peak_height": s.peak_height,
                "chia_peer_count": s.chia_peer_count,
                "subscription_peer_count": s.subscription_peer_count,
                "chia_peer_peak_height": s.chia_peer_peak_height,
                "watched_addresses": s.watched_addresses,
            }),
        ),
        // Only the local wallet DB can fail here — there is no chain call to blame.
        Err(e) => control_error(
            id,
            ErrorCode::WalletReadFailed,
            format!("control.wallet.syncStatus: reading the local wallet sync state failed: {e}"),
        ),
    }
}

/// `control.peerCounts` (dig_ecosystem#2501) — how many peers this node holds on EACH network.
///
/// Two unrelated numbers, each named for its network, because they are routinely confused:
/// `dig_peer_count` is the DIG content/gossip pool (the same figure `control.peerStatus` reports
/// as `connected_peers`), and `chia_peer_count` is Chia full nodes this node HOLDS, whose pool
/// serves its chain reads (dig_ecosystem#2806 — before that it reported the replica's single
/// subscription session instead, so a node holding five peers said one). Neither is
/// `control.peerStatus`'s `relay.peer_count`, which counts peers connected to the
/// RELAY rather than to this node — and which, being the only lively-looking number in that
/// payload, is the one that gets misread.
///
/// A third number answers a third question: `known_dig_peer_count` is how many DIG peers this node
/// has LEARNED OF, connected or not (dig_ecosystem#2570). It separates a REACHABILITY fault — no
/// connections despite a full address book — from a DISCOVERY fault, which `dig_peer_count: 0`
/// alone cannot distinguish. It is ONE node's local view and a lower bound, never the size of the
/// network, and it is never derived from the connected count.
///
/// `null` means UNOBSERVABLE, never zero: a count nobody could take is not a count of none.
/// `chia_peer_count` is taken from the SAME accessor `control.wallet.syncStatus` uses, so the two
/// methods cannot disagree.
async fn peer_counts(ctx: &ControlCtx, id: Value) -> Value {
    let chia_peer_count = ctx
        .wallet
        .wallet_sync_status()
        .await
        .ok()
        .and_then(|s| s.chia_peer_count);
    let dig_peer_status = dig_peer_status(ctx).await;
    let count = |key: &str| {
        dig_peer_status
            .as_ref()
            .and_then(|status| status[key].as_u64())
            .and_then(|n| u32::try_from(n).ok())
    };
    control_ok(
        id,
        json!({
            "dig_peer_count": count("connected_peers"),
            "chia_peer_count": chia_peer_count,
            "known_dig_peer_count": count("known_peers"),
        }),
    )
}

// ---------------------------------------------------------------------------
// Trusted CHIA full-node peers (dig_ecosystem#2870)
// ---------------------------------------------------------------------------

/// What a trusted Chia peer costs, in one sentence, on the wire.
///
/// A `user_managed` peer row is the ONLY way to reach
/// [`dig_wallet::sage::sync::PeerTrust::Operator`], which is authoritative for money WITHOUT a
/// quorum: it may drive catch-up, rollback and the `initial_sync_complete` flag on its own word.
/// Every other peer is `Discovered` and must be agreed with by independently chosen peers first.
///
/// Stated here, once, and returned by `control.chiaPeers.add` so that a client renders the cost
/// from the node's own answer instead of restating it locally and drifting away from it.
///
/// The authorising scope is deliberately narrow: **a node you run yourself**. NC-12 permits the
/// operator to declare a node THEIR OWN, and that is what justifies the unbounded authority the
/// entry carries. Widening it to vouching or recommending moves the case outside the
/// justification, and "a node you vouch for" is a phrase somebody can be talked into applying to
/// a stranger's address. [`the_trust_wording_authorises_only_a_node_the_operator_runs`] holds the
/// line here and in the CLI help.
const CORROBORATION_BYPASS_NOTICE: &str = concat!(
    "This peer is now TRUSTED: chain answers from it are accepted on their own, with no ",
    "corroboration from other peers. A wrong or hostile trusted peer can give this node a ",
    "false view of the chain, and of your money. Add only a node you run yourself."
);

/// What `control.chiaPeers.add` says when the entry was un-banned but NOT granted trust.
///
/// The call succeeded and the person still needs to be told what actually happened: the peer is
/// dialable again, and it is still subject to corroboration. Reporting the bypass notice here
/// instead would be a claim about custody-grade authority that nothing granted.
const UNBANNED_WITHOUT_TRUST_NOTICE: &str = concat!(
    "This peer is no longer banned, but it was NOT granted trust: chain answers from it still ",
    "require corroboration from other peers. `dign chia-peers remove <ip>` then ",
    "`dign chia-peers add <ip>` if you meant to trust it."
);

/// `control.chiaPeers.add` — start trusting a Chia full node.
///
/// A THIN dispatch to [`dig_wallet::sage::rpc::WalletBackend::add_peer`], the one writer of the
/// `peers` table. Nothing here decides what a peer is, and nothing here writes a second list.
async fn chia_peers_add(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let ip = match canonical_ip(params, "control.chiaPeers.add") {
        Ok(ip) => ip,
        Err(refusal) => return refusal(id),
    };
    match ctx
        .wallet
        .add_peer_reporting_trust(&dig_wallet::sage::types::AddPeer { ip: ip.clone() })
        .await
    {
        // `trusted` is the RESULTING state, read back from the row -- not a restatement of what
        // was asked for. Adding a peer that was BANNED un-bans it and grants no bypass, so a
        // constant `true` here would tell an operator they had configured a trusted node while
        // they were still silently depending on the corroboration they were told they bypassed.
        Ok(trusted) => control_ok(
            id,
            json!({
                "added": true,
                "ip": ip,
                "port": dig_wallet::sage::network::DEFAULT_PEER_PORT,
                "corroboration_bypassed": trusted,
                "notice": if trusted {
                    CORROBORATION_BYPASS_NOTICE
                } else {
                    UNBANNED_WITHOUT_TRUST_NOTICE
                },
            }),
        ),
        Err(e) => control_error(id, ErrorCode::ControlError, format!("add_peer failed: {e}")),
    }
}

/// `control.chiaPeers.list` — the tracked Chia peers: trusted, discovered and BANNED alike.
///
/// Nothing is filtered out, and each exclusion is reported as a flag instead. `user_managed` tells
/// the trusted set from the discovered one; a list that showed only the trusted set would let a
/// person conclude their node talks to nobody else, which is the opposite of true. `banned` is
/// reported for the same reason turned around: this is the ONLY enumeration of the ban list, and a
/// blocklist a person cannot read is a blocklist they cannot correct.
async fn chia_peers_list(ctx: &ControlCtx, id: Value) -> Value {
    match ctx.wallet.get_peers().await {
        Ok(resp) => {
            let peers: Vec<Value> = resp.peers.iter().map(chia_peer_wire).collect();
            control_ok(id, json!({ "peers": peers }))
        }
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("get_peers failed: {e}"),
        ),
    }
}

/// One tracked Chia peer, as `control.chiaPeers.list` reports it. PURE.
///
/// This is where `peak_height` becomes `null`: the wallet DB column is `NOT NULL DEFAULT 0` and no
/// writer sets it yet, so a `0` means "nobody has polled this peer" rather than "this peer is at
/// genesis". Those must not read the same — a stale peer the operator believes WITHOUT
/// corroboration is exactly what this field exists to reveal.
///
/// The mapping lives HERE rather than in `PeerRecord`, so the Sage-parity `get_peers` body keeps
/// the integer a strict third-party client deserializes into a non-optional field. One honest shape
/// on this node's own surface, one unchanged parity shape, no divergent internal type.
///
/// When per-peer telemetry lands, the column must become nullable and this `> 0` test must go with
/// it, or a genuine genesis height will be reported as unobserved.
fn chia_peer_wire(p: &dig_wallet::sage::types::PeerRecord) -> Value {
    json!({
        "ip": p.ip_addr,
        "port": p.port,
        "peak_height": (p.peak_height > 0).then_some(p.peak_height),
        "user_managed": p.user_managed,
        "banned": p.banned,
    })
}

/// `control.chiaPeers.remove` — stop trusting a Chia full node, optionally banning it.
async fn chia_peers_remove(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let ip = match canonical_ip(params, "control.chiaPeers.remove") {
        Ok(ip) => ip,
        Err(refusal) => return refusal(id),
    };
    let ban = params.get("ban").and_then(Value::as_bool).unwrap_or(false);
    match ctx
        .wallet
        .remove_peer_reporting_match(&dig_wallet::sage::types::RemovePeer {
            ip: ip.clone(),
            ban,
        })
        .await
    {
        // `outcome`, and NO `removed: true` companion, so a consumer has to MATCH and cannot
        // render "nothing was there" as "it is gone". This is the only way to un-trust a peer
        // holding unbounded authority over the wallet replica, so a remedy that cannot report its
        // own failure would leave an operator believing they revoked trust they still grant. The
        // usual cause of a miss is an address spelled differently from the stored one -- which is
        // why both sides canonicalise.
        Ok(matched) => control_ok(
            id,
            json!({
                "outcome": if matched { "removed" } else { "no_such_peer" },
                "ip": ip,
                "banned": ban,
            }),
        ),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("remove_peer failed: {e}"),
        ),
    }
}

/// `params.ip` in the CONTRACT's canonical form, or a ready-made refusal.
///
/// Canonicalising on the way IN is what makes one peer one key. `2001:0DB8:0000::1` and
/// `2001:db8::1` are the same host typed two ways, and stored verbatim they become two rows: the
/// operator adds trust under one spelling, tries to remove it under the other, is told nothing
/// matched, and the peer they meant to un-trust is still believed WITHOUT corroboration. That is
/// an un-trust that silently does not happen, so both handlers canonicalise through the same
/// function the contract defines rather than trimming and hoping.
///
/// Rejecting a non-literal also BOUNDS the ban list: `remove { ban: true }` persists a row keyed
/// by this string, so an unvalidated key is unbounded at-rest growth driven by one small call.
/// A hostname, a bracketed form, an `ip:port` and a blank string are all refused here rather than
/// stored — a blank in particular is a perfectly storable row, and a tolerant parser would create
/// a trusted peer nobody can dial or delete.
fn canonical_ip(params: &Value, method: &str) -> Result<String, Box<dyn FnOnce(Value) -> Value>> {
    let Some(raw) = params.get("ip").and_then(Value::as_str) else {
        let method = method.to_string();
        return Err(Box::new(move |id| {
            control_error(
                id,
                ErrorCode::InvalidParams,
                format!("{method} requires params.ip (the peer's IP address)"),
            )
        }));
    };
    dig_node_control_interface::params::canonical_peer_ip(raw).map_err(|e| {
        let message = e.message;
        Box::new(move |id| control_error(id, ErrorCode::InvalidParams, message))
            as Box<dyn FnOnce(Value) -> Value>
    })
}

/// The node's own `control.peerStatus` snapshot, or `None` when the peer network is not running.
///
/// A not-running network cannot observe ANY of its counts, so the caller reports them all as
/// `null`. Reading each count out of the returned object individually keeps a count the snapshot
/// omits — an older field, or one the peer layer could not sample — `null` too, which is a
/// different fact from an observed zero.
async fn dig_peer_status(ctx: &ControlCtx) -> Option<Value> {
    let req = json!({
        "jsonrpc": "2.0", "id": 1, "method": "control.peerStatus", "params": {}
    });
    let parsed = dig_node_core::handle_rpc(
        &ctx.node,
        req,
        dig_node_core::download::ReadOrigin::Local,
        dig_node_core::download::RequestProvenance::FirstParty,
    )
    .await;
    parsed["result"]["running"]
        .as_bool()
        .unwrap_or(false)
        .then(|| parsed["result"].clone())
}

/// `control.wallet.broadcast` (dig_ecosystem#2376) — push an ALREADY-SIGNED spend bundle.
///
/// # The custody boundary (§908)
///
/// The params carry signed bytes and nothing else: no key, no seed, no unsigned plan. The USER's
/// key never enters the node — its role on the money path is to read chain state and to relay what
/// somebody else signed.
///
/// The node's OWN custodied wallet is a different matter: it holds real $DIG and it signs on
/// request, so a token holder could sign through the node and hand the bundle back here. While
/// `DIG_WALLET_ENABLE_LIVE_BROADCAST` is off, a bundle spending the node's own coins is refused
/// with `WALLET_NODE_SPEND_DISABLED` (§18.12).
///
/// # TOKEN-GATED, unlike the reads
///
/// This is not an open read ([`is_open_control_read`]), so an `UNAUTHORIZED` from it means exactly
/// that and the remedy is the control token.
///
/// # A refusal is a RESULT
///
/// A mempool that examined the bundle and refused it answers `{accepted:false, rejection}` with a
/// `200`. Failing to REACH a mempool is an error. Collapsing the two turns "your wifi dropped" into
/// "your mint failed", and the remedies are opposite.
async fn wallet_broadcast(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    use dig_wallet::sage::rpc::PushError;

    let Some(hex) = params.get("signed_bundle_hex").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.wallet.broadcast requires params.signed_bundle_hex (hex of a signed \
             SpendBundle)",
        );
    };
    match ctx.wallet.push_signed_bundle(hex).await {
        Ok(outcome) => control_ok(
            id,
            json!({
                "accepted": outcome.accepted,
                "transaction_id": outcome.transaction_id,
                "rejection": outcome.rejection,
            }),
        ),
        Err(PushError::InvalidBundle(e)) => control_error(id, ErrorCode::InvalidParams, e),
        Err(PushError::NoChainSource) => control_error(
            id,
            ErrorCode::WalletNoChainSource,
            "this node has no chain source to push through",
        ),
        Err(PushError::NodeCustodiedSpend) => control_error(
            id,
            ErrorCode::WalletNodeSpendDisabled,
            "this bundle spends the node's own custodied coins; this node may not send its own \
             money (DIG_WALLET_ENABLE_LIVE_BROADCAST is off)",
        ),
        Err(PushError::Unreachable(e)) => control_error(
            id,
            ErrorCode::WalletReadFailed,
            format!("the bundle never reached a mempool: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// The externally-registered watch list (SPEC §18.6f, dig_ecosystem#2823)
// ---------------------------------------------------------------------------

/// The three watch methods are MUTATIONS: they aim this node's chain subscriptions, so they are
/// deliberately absent from [`is_open_control_read`] and therefore require the control token.
///
/// # What they are for
///
/// Under §908 the user's account lives in dig-app and the node custodies no seed, so custody
/// contributes no puzzle hashes at all, the sync supervisor refuses a catch-up over the empty set,
/// and the replica never advances. Registering the account's PUBLIC keys is the only way such a
/// node can follow its user's coins. No seed crosses and nothing here can sign.
///
/// `control.wallet.watch` — register G1 public keys to follow. Idempotent, so a client may
/// re-announce its account on every unlock.
async fn wallet_watch(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let keys = match parse_watch_keys("control.wallet.watch", &id, params) {
        Ok(k) => k,
        Err(e) => return e,
    };
    // Routed through the backend rather than straight at the registry, and the registry's own
    // `watch` is `pub(crate)` so this is the only door there is. Enrolment widens the set of
    // addresses reads treat as replica-backed; the replica answers for that widened set only once a
    // sync records covering it (dig_ecosystem#2871).
    let Some(added) = ctx.wallet.watch_keys(&keys) else {
        return no_watchlist(id);
    };
    let watched = ctx
        .wallet
        .watchlist()
        .map_or(0, |registry| registry.registered().len());
    control_ok(id, json!({ "added": added, "watched": watched }))
}

/// `control.wallet.unwatch` — deregister keys, which genuinely stops the following: they leave the
/// set the supervisor re-reads AND the persisted set a restart would load.
fn wallet_unwatch(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let keys = match parse_watch_keys("control.wallet.unwatch", &id, params) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let Some(registry) = ctx.wallet.watchlist() else {
        return no_watchlist(id);
    };
    let removed = registry.unwatch(&keys);
    control_ok(
        id,
        json!({ "removed": removed, "watched": registry.registered().len() }),
    )
}

/// `control.wallet.watched` — the keys currently registered, so a client can reconcile what it
/// asked for against what the node is actually following.
fn wallet_watched(ctx: &ControlCtx, id: Value) -> Value {
    let Some(registry) = ctx.wallet.watchlist() else {
        return no_watchlist(id);
    };
    control_ok(id, json!({ "public_keys": registry.registered_hex() }))
}

// -- Coin reservations (dig_ecosystem#3127) ----------------------------------
//
// The cross-process half of coin reservation. dig-account holds the wallet-layer seam for callers
// inside ONE process; these three methods let a SECOND process — dig-app, over this control
// interface — narrow against the same set, so two processes sharing one wallet cannot select the
// same coin.
//
// Authority is settled and normative (SPEC §18.26.1): where a node is reachable, THIS node's set
// is authoritative and a client defers to it. A client-local set is the no-node fallback only.
//
// §908 binds all three: reservation is BOOKKEEPING. A coin id is a public chain fact; nothing here
// holds a key, signs anything, or authorizes anything.

/// `control.wallet.reservations.held` — the coins committed to in-flight spends.
///
/// Takes no parameters on purpose. A caller-supplied instant would be a lapse oracle: a far-future
/// value makes every live hold read as expired, which is a free way to defeat the whole set. The
/// node reads its OWN clock and reports it as `as_of_unix` so a client can see skew rather than
/// impose it.
///
/// TOKEN-GATED although it is a read, for the same reason as `control.wallet.watched`: the caller
/// supplies nothing, so the answer describes this node's own state rather than a public chain fact
/// the caller already named.
///
/// A read failure is `WALLET_RESERVATIONS_UNAVAILABLE`, NEVER an empty list. `reserved: []` is a
/// positive statement that nothing is held and permits a caller to spend; "I cannot tell" must
/// stop one. Collapsing the two restores the double-select this exists to prevent.
async fn wallet_reservations_held(ctx: &ControlCtx, id: Value) -> Value {
    match ctx.wallet.reservations_held().await {
        Ok((rows, now_ms)) => control_ok(
            id,
            json!({
                "reserved": rows
                    .iter()
                    .map(|r| json!({
                        "coin_id": r.coin_id,
                        "reservation_id": r.reservation_id,
                        "expires_at_unix": ms_to_unix(r.expires_at_ms),
                    }))
                    .collect::<Vec<_>>(),
                "as_of_unix": ms_to_unix(now_ms),
            }),
        ),
        Err(e) => reservations_unavailable(id, &e),
    }
}

/// The most coins `control.wallet.reservations.reserve` will hold in ONE call.
///
/// The array is bounded BEFORE anything else touches it, and this is a resource bound rather
/// than a shape rule (dig_ecosystem#3127 security gate, finding 1).
///
/// `reserve` does O(N) SQLite work while holding the write lock, and the ingress limiter at
/// `server.rs:1106` covers `is_open_control_read` methods ONLY — these are token-gated, so it
/// does not cover them. Unbounded, one large call stalls concurrent legitimate reserves past
/// `busy_timeout`, and a stalled reserve surfaces as WALLET_RESERVATIONS_UNAVAILABLE: "do not
/// spend" when the truth is "wait". That is the disposition inversion the write-before-read
/// ordering removes elsewhere, reached here by resource pressure instead of a wrong match arm.
///
/// The number is taken from the protocol's own ceilings rather than picked. A control frame is
/// capped at 1 MiB (dig-ipc-protocol `MAX_FRAME_BYTES`), and a coin id costs ~67 bytes as JSON,
/// so a frame can carry ~15,600 ids — bounded, but 15x more work under the lock than anything
/// legitimate. Chia's block cost limit bounds a REAL bundle to a few hundred inputs, so 1,000
/// sits above every honest request and an order of magnitude below the abusive ceiling. It
/// matches the contract's own `COINS_BY_PARENT_MAX_LIMIT` in both value and spirit.
const MAX_RESERVE_COIN_IDS: usize = 1_000;

/// The bound must stay well BELOW what one control frame could carry, which is the ceiling it was
/// chosen to sit under: a 1 MiB frame (dig-ipc-protocol `MAX_FRAME_BYTES`) at ~67 JSON bytes per
/// coin id is ~15,600 ids.
///
/// A compile-time assertion rather than a test: it is a relationship between two constants, so
/// there is no run to observe it in, and a raised bound should fail the BUILD rather than a suite
/// somebody might not run.
const _: () = assert!(
    MAX_RESERVE_COIN_IDS * 15 < (1024 * 1024) / 67,
    "MAX_RESERVE_COIN_IDS has drifted up toward the control-frame ceiling it sits under"
);

/// Why a reservation batch of `len` ids is refused, or `None` when it is within bounds.
///
/// Split out from the handler so the boundary can be pinned from BOTH sides -- at the bound and
/// one over -- without standing up a whole `ControlCtx`. A bound tested only from above can only
/// confirm itself; it cannot notice an off-by-one that refuses a legitimate request.
fn reserve_batch_refusal(len: usize) -> Option<String> {
    (len > MAX_RESERVE_COIN_IDS).then(|| {
        format!(
            "params.coin_ids holds {len} ids, above the {MAX_RESERVE_COIN_IDS} this node will              reserve in one call. Split the request; a bundle that legitimately needs more inputs              than this could not fit in a block anyway"
        )
    })
}

/// `control.wallet.reservations.reserve` — atomically hold coins, all of them or none.
///
/// A clash is `WALLET_COINS_RESERVED`, deliberately distinct from any shortfall: the user HAS the
/// money, it is briefly committed elsewhere, and it returns when that spend settles or its hold
/// lapses. Reporting insufficient funds would send a person to an exchange to solve a wait.
///
/// The returned `ttl_secs` is the lifetime this node APPLIED, which may be shorter than the one
/// requested — a caller told its own figure would wait on a schedule this node does not keep.
async fn wallet_reservations_reserve(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.wallet.reservations.reserve";

    // An ABSENT `coin_ids` is malformed, while an EMPTY one is a legitimate no-op that yields a
    // handle holding nothing. Defaulting the absent case to empty would turn a client bug into a
    // silent success, so the two are kept apart.
    let Some(raw) = params.get("coin_ids") else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{METHOD}: params.coin_ids is required"),
        );
    };
    let Some(items) = raw.as_array() else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{METHOD}: params.coin_ids must be an array of coin-id strings"),
        );
    };
    // Length is checked on the raw array, before per-id validation, so a huge malformed batch is
    // refused without paying to validate it.
    if let Some(why) = reserve_batch_refusal(items.len()) {
        return control_error(id, ErrorCode::InvalidParams, format!("{METHOD}: {why}"));
    }

    // Shape comes from the CONTRACT's own validator, never a local re-derivation: it normalizes a
    // `0x` prefix away, holds every id to lowercase 64-hex, and refuses the WHOLE request when any
    // one is malformed rather than the well-formed subset. Re-deriving that rule here would be a
    // rival implementation of a published contract, and the two would drift.
    //
    // Validating is not merely tidiness. An unvalidated id is a string this node stores as a
    // PRIMARY KEY and then compares against real coin ids; a malformed one can never match a coin,
    // so it would occupy the table until its TTL while protecting nothing.
    let reserve_params =
        match serde_json::from_value::<WalletReservationsReserveParams>(params.clone())
            .map_err(|e| e.to_string())
            .and_then(|p| p.validated().map_err(|e| e.message))
        {
            Ok(p) => p,
            Err(message) => {
                return control_error(id, ErrorCode::InvalidParams, format!("{METHOD}: {message}"));
            }
        };

    match ctx
        .wallet
        .reserve_coins(&reserve_params.coin_ids, reserve_params.ttl_secs)
        .await
    {
        Ok(r) => control_ok(
            id,
            json!({
                "reservation_id": r.reservation_id,
                "coin_ids": r.coin_ids,
                "expires_at_unix": ms_to_unix(r.expires_at_ms),
                // The lifetime the node APPLIED, reported by the same call that applied it.
                // Echoing the caller's request is how a client ends up scheduling a release
                // against a lifetime this node never granted.
                "ttl_secs": (r.ttl_ms.max(0) as u64) / 1000,
            }),
        ),
        Err(ReserveClientCoinsError::Reserved { coin_ids }) => control_error(
            id,
            ErrorCode::WalletCoinsReserved,
            format!(
                "{} coin(s) are committed to a live spend; nothing was reserved. This is a wait, \
                 not a shortfall",
                coin_ids.len()
            ),
        ),
        Err(ReserveClientCoinsError::Unavailable(e)) => reservations_unavailable(id, &e),
    }
}

/// `control.wallet.reservations.release` — free a hold now, ahead of its TTL.
///
/// A handle naming no live reservation is a SUCCESS with `released: false`. A caller releasing on
/// confirmation cannot know whether the TTL got there first, and making the ordinary outcome an
/// error teaches callers to stop checking the result — which is how a release path quietly stops
/// being called, and a release path that stops being called is a funds lockout waiting to happen.
async fn wallet_reservations_release(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.wallet.reservations.release";
    let Some(handle) = params.get("reservation_id").and_then(Value::as_str) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{METHOD}: params.reservation_id is required and must be a string"),
        );
    };
    match ctx.wallet.release_reservation(handle).await {
        Ok(coin_ids) => control_ok(
            id,
            json!({ "released": !coin_ids.is_empty(), "coin_ids": coin_ids }),
        ),
        Err(e) => reservations_unavailable(id, &e),
    }
}

/// The one fail direction for all three reservation methods: REFUSE.
///
/// The underlying error is deliberately NOT interpolated into the message. It is a database error
/// whose text can carry a file path, and a control response is a lower-trust surface than the log.
fn reservations_unavailable(id: Value, e: &dyn std::fmt::Display) -> Value {
    tracing::warn!(error = %e, "the coin-reservation set could not be read");
    control_error(
        id,
        ErrorCode::WalletReservationsUnavailable,
        "the node's coin-reservation set could not be read, so coin selection cannot be trusted",
    )
}

/// Milliseconds since the epoch to whole seconds, the unit the control contract speaks.
///
/// Saturating at zero rather than wrapping: a negative instant is not representable in the wire's
/// `u64`, and a wrap would turn a nonsense clock into a hold that reads as lasting for eons.
fn ms_to_unix(ms: i64) -> u64 {
    ms.max(0) as u64 / 1000
}

/// Parse `params.public_keys` — a non-empty array of 48-byte G1 keys as hex.
///
/// ALL-OR-NOTHING, deliberately: registering only the entries that happened to parse would leave
/// the node following a strict subset of the account and reporting a balance that is too small
/// rather than obviously broken (dig_ecosystem#2762). A malformed request is refused whole, so the
/// client learns immediately instead of reading a quiet under-report as the truth.
fn parse_watch_keys(
    method: &str,
    id: &Value,
    params: &Value,
) -> std::result::Result<Vec<dig_wallet::sage::watchlist::WatchKey>, Value> {
    let Some(entries) = params.get("public_keys").and_then(|v| v.as_array()) else {
        return Err(control_error(
            id.clone(),
            ErrorCode::InvalidParams,
            format!("{method} requires params.public_keys (an array of 48-byte G1 keys as hex)"),
        ));
    };
    if entries.is_empty() {
        return Err(control_error(
            id.clone(),
            ErrorCode::InvalidParams,
            format!("{method} requires at least one key in params.public_keys"),
        ));
    }
    let mut keys = Vec::with_capacity(entries.len());
    for entry in entries {
        let parsed = entry
            .as_str()
            .and_then(dig_wallet::sage::watchlist::decode_key);
        match parsed {
            Some(k) => keys.push(k),
            None => {
                return Err(control_error(
                    id.clone(),
                    ErrorCode::InvalidParams,
                    format!(
                        "{method} received an entry in params.public_keys that is not a 48-byte \
                         G1 public key as hex; no key was registered"
                    ),
                ))
            }
        }
    }
    Ok(keys)
}

/// This node has no watch registry attached, so it cannot follow anything on request.
///
/// Refused rather than answered with a cheerful zero: a client told its account is being followed
/// while nothing watches it reads the resulting empty balance as the truth.
fn no_watchlist(id: Value) -> Value {
    control_error(
        id,
        ErrorCode::WalletNoChainSource,
        "this node has no wallet watch registry, so it cannot follow externally-registered \
         addresses",
    )
}

/// Map a coin read onto the wire contract published by `dig-node-control-interface`.
///
/// The `asset` is echoed onto every coin because dig-app's frozen `CoinRecord` carries one and
/// filters by it; the read is already scoped to a single asset, so echoing the REQUESTED one is
/// exactly what the coins are.
fn coins_wire(r: &dig_wallet::sage::rpc::WalletCoinsResult, asset: BalanceAsset) -> Value {
    // Serialized through the published `Asset`, so the echo is spelled exactly as the contract
    // spells it — `"dig"` for $DIG, `{"cat":"<hex>"}` for any other CAT — and never `null`.
    let asset = serde_json::to_value(ControlAsset::from(asset))
        .expect("an Asset always serializes to a token or a one-key map");
    json!({
        "coins": r.coins.iter().map(|c| json!({
            "coin_id": c.coin_id,
            "asset": asset,
            "amount": c.amount,
            "parent_coin_info": c.parent_coin_info,
            "puzzle_hash": c.puzzle_hash,
            "created_height": c.created_height,
            // Every coin an address-scoped read returns is unspent, so this is `null` here —
            // but it is the COIN's own value, not a literal, so the shape stays truthful if the
            // read's filtering ever changes.
            "spent_height": c.spent_height,
        })).collect::<Vec<_>>(),
        "source": r.source.as_wire(),
        "synced": r.synced,
        "peak_height": r.peak_height,
    })
}

/// Map a by-id coin read onto the wire contract published by `dig-node-control-interface`.
///
/// `asset` is ALWAYS `null` here, unlike [`coins_wire`]. A coin id alone does not reveal whether a
/// coin is XCH, a CAT or a singleton — that needs the puzzle, which this read never inspects — so
/// naming one would be asserting a classification the node did not verify.
fn coin_by_id_wire(r: &dig_wallet::sage::rpc::WalletCoinByIdResult) -> Value {
    json!({
        "coin": r.coin.as_ref().map(|c| json!({
            "coin_id": c.coin_id,
            "asset": Value::Null,
            "amount": c.amount,
            "parent_coin_info": c.parent_coin_info,
            "puzzle_hash": c.puzzle_hash,
            "created_height": c.created_height,
            "spent_height": c.spent_height,
        })),
        "source": r.source.as_wire(),
        "synced": r.synced,
        "peak_height": r.peak_height,
    })
}

/// One coin as the by-coin reads publish it: every field the contract's `WalletCoinRecord` names,
/// with `asset` explicitly `null`.
///
/// Shared by [`coin_spend_wire`] and [`coins_by_parent_wire`] because they classify nothing for the
/// SAME reason [`coin_by_id_wire`] does not — the subject is named by a coin id or a parent, never
/// by an asset — and two hand-written copies of a record shape are two places for a field to go
/// missing. `coin_by_id_wire` is left inlined rather than folded in: it is the pinned reference
/// shape three tests assert against literally, and rewriting it to prove a point about the new
/// methods would put those tests' subject behind an indirection.
fn unclassified_coin_wire(c: &dig_wallet::sage::rpc::WalletCoin) -> Value {
    json!({
        "coin_id": c.coin_id,
        "asset": Value::Null,
        "amount": c.amount,
        "parent_coin_info": c.parent_coin_info,
        "puzzle_hash": c.puzzle_hash,
        "created_height": c.created_height,
        "spent_height": c.spent_height,
    })
}

/// Map a coin-SPEND read onto the wire contract published by `dig-node-control-interface`.
///
/// `spend: null` is emitted as an explicit null member rather than an omitted key: the contract
/// decodes this field with `required_option`, so an absent key is a decode FAILURE on the client
/// and not a verdict. That is deliberate on both sides — "no spend" must be something the node
/// actually said.
fn coin_spend_wire(r: &dig_wallet::sage::rpc::WalletCoinSpendResult) -> Value {
    json!({
        "spend": r.spend.as_ref().map(|s| json!({
            "coin": unclassified_coin_wire(&s.coin),
            "puzzle_reveal": s.puzzle_reveal,
            "solution": s.solution,
        })),
        "source": r.source.as_wire(),
        "synced": r.synced,
        "peak_height": r.peak_height,
    })
}

/// Map a children PAGE onto the wire contract published by `dig-node-control-interface`.
///
/// `complete` and `cursor` are both emitted unconditionally. The contract spells the flag
/// positively — `complete`, not `truncated` — precisely so that the reading a client falls into when
/// the field is missing or defaulted is "there may be more", and it decodes `cursor` with
/// `required_option` so an absent key cannot become a confident "nothing to resume from".
fn coins_by_parent_wire(r: &dig_wallet::sage::rpc::WalletCoinsByParentResult) -> Value {
    json!({
        "coins": r.coins.iter().map(unclassified_coin_wire).collect::<Vec<_>>(),
        "complete": r.complete,
        "cursor": r.cursor,
        "source": r.source.as_wire(),
        "synced": r.synced,
        "peak_height": r.peak_height,
    })
}

/// Count distinct store ids among the cached capsules. PURE-ish (reads the slice).
fn distinct_store_count(cached: &[dig_node_core::CachedCapsule]) -> usize {
    cached
        .iter()
        .map(|c| c.store_id.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

// -- Profile bodies (epic #3008, W6) -----------------------------------------------------------
//
// `control.profile.putBody` / `control.profile.getBody`. Both TOKEN-GATED by the default rule
// (only the explicit OPEN set skips the token), because a `putBody` decides what this node will
// serve to the whole network under a profile id.
//
// The trust boundary is the point of these two handlers: **dig-app gets no exemption.** It holds
// the key and signs the root (§908), but the bytes reach the node exactly as a peer's bytes do, so
// the SAME check binds both entry points —
// [`profile_sync::accept_local_body`](dig_node_core::seams::dig_peer::profile_sync::accept_local_body)
// independently resolves the root on chain, requires the caller's claimed root to BE that root, and
// only then verifies the bytes against it. One implementation of the check serves the gossip gate
// and the control plane alike; a second one would be a second place for it to be wrong.

/// The maximum DECODED body size, taken from the control interface rather than restated, so this
/// node and every client agree on the bound by construction.
use base64::Engine as _;
use dig_node_core::seams::dig_peer::profile_sync::MAX_PROFILE_BODY_BYTES;

/// Parse a lowercase, unprefixed 64-hex field into its 32 raw bytes.
///
/// Strict about case and length: every downstream comparison is over `[u8; 32]`, and a
/// case-forgiving text parse is exactly the kind of slack that turns a byte comparison back into a
/// text one somewhere further down.
fn parse_hex32_param(
    method: &str,
    field: &str,
    id: &Value,
    params: &Value,
) -> std::result::Result<[u8; 32], Value> {
    let invalid = |detail: &str| {
        control_error(
            id.clone(),
            ErrorCode::InvalidParams,
            format!("{method} requires params.{field} as lowercase 64-hex ({detail})"),
        )
    };
    let text = params
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid("missing or not a string"))?;
    if text.len() != 64 || text.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(invalid("wrong length or not lowercase"));
    }
    let raw = hex::decode(text).map_err(|_| invalid("not hex"))?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| invalid("not 32 bytes"))
}

/// The profile-body store this node persists to and serves from.
fn profile_body_store(ctx: &ControlCtx) -> ProfileBodyStore {
    ProfileBodyStore::under_cache_dir(ctx.node.cache_dir_path())
}

/// Flood one 223 announce for a body this node has just persisted, returning
/// `(peers reached, peers connected but unreachable)`.
///
/// Zero reached is an honest answer with THREE causes — no peer network on this node, no peers
/// connected, or peers connected that this node cannot push to (lazy or NAT-bound) — and none is an
/// error: the body is on disk either way, and the periodic re-announce loop tells whoever connects
/// next.
///
/// The unreachable count is reported beside it because dig-gossip 0.25.0 made the reach count a TRUE
/// delivery count (dig_ecosystem#3063): peers it previously counted as delivered-to are now excluded,
/// so `0` alone can no longer distinguish "nobody is out there" from "peers are out there and none
/// could be pushed to". Reporting one number without the other would move that ambiguity onto the
/// caller.
async fn announce_now(ctx: &ControlCtx, store_id: [u8; 32], root: [u8; 32]) -> (usize, usize) {
    let Some(handle) = ctx.node.gossip_handle() else {
        return (0, 0);
    };
    // Originated by this node (it just persisted the body), so the dedup-exempt path: re-putting an
    // unchanged `(store_id, root)` produces a byte-identical frame, and under the forwarding
    // broadcast every announce after the first was silently dropped (dig_ecosystem#3061).
    let reached = handle
        .broadcast_local(announce_frame(store_id, root), None)
        .await
        .unwrap_or(0);
    (reached, handle.unreachable_peer_count())
}

/// `control.profile.putBody` — persist a profile body, but ONLY once the chain confirms its root.
///
/// Refusal is always an error, never an `Ok` carrying `stored: false`: a caller that reads a
/// success flag would have to remember to check it, and the one that forgets believes the network
/// is serving bytes that were rejected.
///
/// There are no profile-specific error codes yet, so a root that is not confirmed and a body that
/// is malformed both surface as `INVALID_PARAMS`. They need OPPOSITE remedies from the caller —
/// wait and retry versus re-encode — so the distinction is carried in the message text until the
/// codes exist (tracked as a follow-up).
async fn profile_put_body(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.profile.putBody";
    let store_id = match parse_hex32_param(METHOD, "store_id", &id, params) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let root = match parse_hex32_param(METHOD, "root", &id, params) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(body_b64) = params.get("body_b64").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{METHOD} requires params.body_b64 (standard base64, padded)"),
        );
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(body_b64) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!("{METHOD}: params.body_b64 is not standard padded base64"),
        );
    };
    // Bounded on the DECODED length, BEFORE anything is persisted: a body past this cannot be
    // served to a peer inside the gossip frame ceiling, so storing one would put something
    // permanently unsyncable on disk.
    //
    // The ceiling is the SERVABLE one, not the control interface's `MAX_BODY_BYTES`. Those two
    // differ — the contract's cap is 4 MiB (half dig-gossip's 8 MiB websocket message ceiling),
    // while a 225 frame can carry only `MAX_PROFILE_BODY_BYTES`. Bounding on the larger number
    // accepts a 1-4 MiB body, persists it, and then can never answer a single 224 for it: exactly
    // the permanently-unsyncable artifact this check says it prevents, produced by the check
    // itself. Refusing at the smaller number is what makes the comment true.
    if bytes.len() > MAX_PROFILE_BODY_BYTES {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!(
                "{METHOD}: body is {} bytes, above the {MAX_PROFILE_BODY_BYTES}-byte maximum a \
                 profile body may be if it is to be servable to peers",
                bytes.len()
            ),
        );
    }

    match accept_local_body(
        &profile_body_store(ctx),
        &*ctx.node.anchored_root_resolver_arc(),
        store_id,
        root,
        &bytes,
    )
    .await
    {
        Ok(_) => {
            // Tell the network immediately, rather than waiting up to `ANNOUNCE_INTERVAL` for the
            // re-announce loop. Peers reached is REPORTED, never a failure: a node with no peer
            // network still persisted and still serves the body over the control plane, and the
            // periodic loop covers every peer that connects later.
            let (announced, unreachable) = announce_now(ctx, store_id, root).await;
            control_ok(
                id,
                json!({
                    "stored": true,
                    "store_id": hex::encode(store_id),
                    "root": hex::encode(root),
                    "body_bytes": bytes.len() as u64,
                    "announced_to_peers": announced as u64,
                    "unreachable_peers": unreachable as u64,
                }),
            )
        }
        Err(e @ (LocalAcceptError::RootNotConfirmed(_) | LocalAcceptError::Malformed(_))) => {
            control_error(id, ErrorCode::InvalidParams, format!("{METHOD}: {e}"))
        }
        // A write failure is this node's fault, not the caller's input, so it must not read as
        // "your parameters were wrong" — the remedy is on this machine.
        Err(e @ LocalAcceptError::Persist(_)) => {
            control_error(id, ErrorCode::ControlError, format!("{METHOD}: {e}"))
        }
    }
}

/// `control.profile.getBody` — the body this node holds at `(store_id, root)`, if it holds one.
///
/// `body_b64: null` means "consulted, holds nothing". A read that FAILED is an error instead: a
/// caller that cannot tell the two apart renders an existing profile as an empty one, and the
/// remedies are opposite (publish it versus fix this node's disk).
///
/// The echoed `root` is always the root the caller asked for — this node never substitutes a newer
/// body it happens to hold.
async fn profile_get_body(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    const METHOD: &str = "control.profile.getBody";
    let store_id = match parse_hex32_param(METHOD, "store_id", &id, params) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let root = match parse_hex32_param(METHOD, "root", &id, params) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match profile_body_store(ctx).get(&store_id, &root) {
        Ok(held) => control_ok(
            id,
            json!({
                "store_id": hex::encode(store_id),
                "root": hex::encode(root),
                "body_b64": held.as_ref().map(|b| {
                    base64::engine::general_purpose::STANDARD.encode(b)
                }),
                "body_bytes": held.map_or(0u64, |b| b.len() as u64),
            }),
        ),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("{METHOD}: the profile body could not be read from disk: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// The automated-spend audit record and the deterministic mirror-coin collateral model.
//
// `control.spends.list` is the ONLY sanctioned reader of the audit record: it is a node-private
// file, and a second process parsing a growing append-only format is how two views of "what did
// the node spend" start disagreeing, on the one subject where disagreeing is least affordable.
// ---------------------------------------------------------------------------------------------

/// `control.spends.list` — one page of the automated-spend audit record.
///
/// Decoding through [`SpendsListParams`] rather than by hand is deliberate: the contract validates
/// the page bound inside its own `Deserialize`, so a limit of `0` or one above the cap is refused
/// here without this handler having to remember to check. A `0` page makes no progress and a caller
/// looping until `complete` would loop forever.
fn spends_list(id: Value, params: &Value) -> Value {
    use dig_node_control_interface::params::SpendsListParams;

    let params: SpendsListParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => return control_error(id, ErrorCode::InvalidParams, e.to_string()),
    };
    // `effective_limit` resolves an omitted limit on the contract's terms, so the node and the
    // client cannot resolve the same absent field to two different page sizes.
    let limit = params.effective_limit() as usize;
    let query = crate::spend_audit::SpendQuery {
        since_ms: params.since_ms,
        until_ms: params.until_ms,
        store_id: params.store_id.clone(),
        kind: params.kind.clone(),
        status: params.status.clone(),
        after_id: params.after_id.clone(),
        limit: Some(limit),
    };

    // `in_state_dir` rather than a path built from `ctx.state_dir`: the audit file has ONE home,
    // and `SpendLog` is the component that knows where it is.
    let log = crate::spend_audit::SpendLog::in_state_dir();
    let ledger = match log.query(&query) {
        Ok(l) => l,
        // A cursor the record does not know is the caller's mistake, not a broken record.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            return control_error(id, ErrorCode::InvalidParams, e.to_string())
        }
        // Anything else means the node could not LOOK. That is never an empty page: "nothing to
        // report" is the answer a person stops investigating on, and it must not be returned for a
        // record that could not be read.
        Err(e) => {
            return control_error(
                id,
                ErrorCode::SpendAuditUnreadable,
                format!("the automated-spend record could not be read: {e}"),
            )
        }
    };

    let cursor = crate::spend_audit::SpendLog::cursor_of(&ledger);
    control_ok(
        id,
        json!({
            "spends": ledger.records.iter().map(spend_row).collect::<Vec<_>>(),
            "complete": ledger.complete,
            // Both keys are always PRESENT. `null` is meaningful here, so an absent key must not
            // decode into it: a truncated payload would otherwise read as a confident "there is
            // nothing to look up".
            "cursor": cursor,
            "unreadable_lines": ledger.unreadable_lines,
        }),
    )
}

/// One audit row on the wire.
///
/// Amounts are decimal STRINGS. They carry the full `u64` range, which does not survive a JSON
/// number through an f64 parser, and a silently rounded figure about somebody's money is exactly
/// the lie this record exists to prevent.
fn spend_row(r: &crate::spend_audit::SpendRecord) -> Value {
    use crate::spend_audit::SpendStatus;

    // The failure STAGE travels with a failure, never a bare "failed": only `Signing` means the
    // money definitely did not move, so flattening the stage would make every client structurally
    // unable to tell a person the truth about their money.
    let status = match &r.status {
        SpendStatus::Pending => json!({ "state": "pending" }),
        SpendStatus::Submitted => json!({ "state": "submitted" }),
        SpendStatus::Confirmed { height, coin_id } => json!({
            "state": "confirmed",
            "height": height,
            "coin_id": coin_id.to_string(),
        }),
        SpendStatus::Failed { stage, reason } => json!({
            "state": "failed",
            "stage": stage.to_string(),
            "reason": reason,
        }),
        SpendStatus::Unresolved { reason } => json!({
            "state": "unresolved",
            "reason": reason,
        }),
    };
    json!({
        "id": r.id,
        "revision": r.revision,
        "kind": r.kind.as_str(),
        "purpose": r.purpose,
        "authority": {
            "principal": r.authority.principal,
            "grant": r.authority.grant,
        },
        "asset": r.asset.to_string(),
        "amount_mojos": r.amount_mojos.to_string(),
        "fee_mojos": r.fee_mojos.to_string(),
        "store_id": r.store_id,
        "initiated_ms": r.initiated_ms,
        "updated_ms": r.updated_ms,
        "status": status,
        "funding_coin_ids": r.funding_coin_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        // Carries its own observed/expected flag, so a client never has to re-derive the
        // distinction between the coin the node INTENDS to create and one it has seen on chain.
        "chain_reference": r.chain_reference().map(|c| json!({
            "coin_id": c.coin_id.to_string(),
            "confirmed": c.confirmed,
        })),
    })
}

/// This node's view of which collateral epoch is in force.
///
/// The mirror-coin epoch schedule is a WALL-CLOCK one published by `dig-constants` — 7-day epochs
/// from a fixed genesis — so the current epoch is derived, not guessed and not stored. It is read
/// through `dig_constants::mirror_epoch_at_unix_ms` rather than recomputed here: the epoch number
/// is an input to coin identity, so a second implementation of the arithmetic would derive
/// different coins rather than merely a different label.
///
/// Deriving it is also what makes a STALE answer unrepresentable. The requirement is looked up for
/// the epoch that is current NOW, so a node whose census has stopped running reports
/// `not_censused` for the present epoch instead of confidently serving last week's figure.
fn current_collateral_epoch() -> crate::collateral::CurrentEpoch {
    crate::collateral::current_epoch_now()
}

/// `control.collateral.requirement` — this epoch's per-store requirement, or a named reason.
///
/// The local safety margin is deliberately not consulted: this figure is the consensus-derived one
/// every node derives identically, and returning the margined amount would make this operator's
/// preference look like the network's price.
fn collateral_requirement(id: Value) -> Value {
    let store = crate::collateral::EpochRecordStore::in_state_dir();
    let answer = crate::collateral::requirement(&store, current_collateral_epoch());
    match serde_json::to_value(&answer) {
        Ok(v) => control_ok(id, v),
        Err(e) => control_error(id, ErrorCode::ControlError, e.to_string()),
    }
}

/// `control.collateral.buffer` — the $DIG this node recommends HOLDING, and the funding state.
///
/// A SEPARATE method from [`collateral_requirement`] because the two figures have different
/// authorities: the requirement is consensus-derived and identical on every node, while this one
/// depends on this node's own served set, an operator preference, and a horizon this node chose.
///
/// **The funding state is carried, not left to the client to re-derive from thresholds.** Two
/// clients deriving it will eventually disagree, and the one that disagrees about a funding warning
/// is the one an operator acts on.
///
/// Today this answers `unknown` with a NAMED reason on most nodes, and that is the honest answer
/// rather than a stub: the served `(owner, store, root)` set is enumerated by the census
/// (dig-node#387), and the operator's spendable balance is not a fact this node holds — it cannot
/// know which address holds their $DIG, and a balance read of the wrong address returns a confident
/// number about the wrong money. A zero would read as "no buffer needed" and have them post nothing.
fn collateral_buffer(id: Value) -> Value {
    let store = crate::collateral::EpochRecordStore::in_state_dir();
    let requirement = crate::collateral::requirement(&store, current_collateral_epoch());
    let margin_bp = crate::collateral::CollateralConfig::load().margin_bp;

    let answer = crate::collateral::buffer_advice(
        // The served set and the spendable balance are both genuinely unknown to the node today, so
        // each is passed as `None` and reported through its own reason. They are NOT approximated
        // from the hosted-store list or from an arbitrary address: a set that merely resembles the
        // served pairs, or a balance for the wrong address, yields a plausible wrong number on a
        // money surface — which is worse than no number.
        None,
        &requirement,
        margin_bp,
        None,
        dig_node_control_interface::params::DEFAULT_BUFFER_HORIZON_EPOCHS,
    );
    match serde_json::to_value(answer) {
        Ok(v) => control_ok(id, v),
        Err(e) => control_error(id, ErrorCode::ControlError, e.to_string()),
    }
}

/// `control.collateral.margin.get` — the node's local safety margin, in basis points.
fn collateral_margin_get(id: Value) -> Value {
    let cfg = crate::collateral::CollateralConfig::load();
    control_ok(id, json!({ "margin_bp": cfg.margin_bp }))
}

/// `control.collateral.margin.set` — persist the margin and return what is now in force.
///
/// A value above the contract's ceiling is REFUSED rather than clamped, and the returned figure is
/// what was actually stored. Clamping and returning the clamped value would leave the caller's
/// stored intent and the node's behaviour disagreeing on the money path.
fn collateral_margin_set(id: Value, params: &Value) -> Value {
    use dig_node_control_interface::params::CollateralMarginSetParams;

    let parsed: CollateralMarginSetParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => return control_error(id, ErrorCode::InvalidParams, e.to_string()),
    };
    let parsed = match parsed.validated() {
        Ok(p) => p,
        Err(e) => return control_error(id, ErrorCode::InvalidParams, e.message),
    };

    let cfg = crate::collateral::CollateralConfig {
        margin_bp: parsed.margin_bp,
    };
    // Persisted before it is reported. A margin that lapsed to the default on reboot would silently
    // change what the node posts, so a write failure must not be answered with a success.
    if let Err(e) = cfg.save() {
        return control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to persist the safety margin: {e}"),
        );
    }
    control_ok(id, json!({ "margin_bp": cfg.margin_bp }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// **Proves:** `control.capsule.fetch` is dispatched, requires a token, and names its params
    /// as the published contract does.
    ///
    /// **Catches:** a method served under a name the contract does not declare (invisible to every
    /// client), or one accidentally admitted to the open-read set — a capsule pull is egress this
    /// node pays for, so any local process being able to trigger it unauthenticated would be a
    /// widening, not a convenience.
    #[test]
    fn the_capsule_fetch_verb_is_served_and_is_not_an_open_read() {
        assert!(
            CONTROL_METHODS.contains(&"control.capsule.fetch"),
            "a handler nothing routes to is dead code; the contract-conformance test pairs with \
             this one from the other direction"
        );
        assert!(
            !is_open_control_read("control.capsule.fetch"),
            "a capsule pull spends this node\'s bandwidth on a stranger\'s choice of content, so \
             it is authorized like every other write on this plane"
        );
    }

    /// **Proves:** the verb refuses anything that is not two canonical 64-hex ids, and says which
    /// fields it wanted.
    ///
    /// **Fixture design — four rejections and one acceptance.** Each rejection varies exactly one
    /// field from a well-formed pair, so a validator that checked only `store`, only `root`, or
    /// only presence-not-shape is caught by a different arm. The accepted pair is the control:
    /// without it, a validator that rejected everything would pass all four.
    #[test]
    fn a_capsule_fetch_takes_exactly_two_canonical_ids() {
        let good = "a1".repeat(32);
        let bad = "not-hex";

        for (store, root, why) in [
            (bad, good.as_str(), "a malformed store"),
            (good.as_str(), bad, "a malformed root"),
            ("", good.as_str(), "a missing store"),
            (good.as_str(), "", "a missing root"),
        ] {
            let params = json!({ "store": store, "root": root });
            assert!(
                capsule_fetch_target(&params).is_err(),
                "{why} must be refused: a pull keyed on a non-canonical id names no generation the \
                 chain could anchor"
            );
        }

        assert_eq!(
            capsule_fetch_target(&json!({ "store": good.to_uppercase(), "root": good })),
            Ok((good.clone(), good.clone())),
            "CONTROL: a well-formed pair must be ACCEPTED through the same argument positions - \
             without this the four refusals prove only that everything is refused - and it is \
             LOWERCASED, because the cache path is built from these ids and a case difference \
             would make one capsule two files"
        );
    }

    /// **The CALLER-ADDRESSED reads are token-less; the arrival cursor and the PUSH are not.**
    ///
    /// Written as the exact expected SET rather than derived from the predicate, so it pins the
    /// membership and not the implementation's opinion of itself. Opening the push would be a
    /// silent, catastrophic widening — any local process could then broadcast — so it must fail a
    /// test rather than pass review.
    #[test]
    fn the_caller_addressed_reads_are_open_and_the_arrival_cursor_and_push_are_not() {
        let open: Vec<&str> = CONTROL_METHODS
            .iter()
            .copied()
            .filter(|m| is_open_control_read(m))
            .collect();
        assert_eq!(
            open,
            vec![
                "control.wallet.balance",
                "control.wallet.coins",
                "control.wallet.coinById",
                // The two chain primitives (dig_ecosystem#2572) are `coinById`'s neighbours, not
                // `arrivals`': each names its subject with a caller-supplied public coin id and
                // answers a deterministic public chain fact, disclosing no node-to-address
                // association. They are also the reads a client needs to implement `ChainSource`
                // over this plane at all, which is what makes a dig-profile mint possible through
                // the node instead of via third-party HTTPS.
                "control.wallet.coinSpend",
                "control.wallet.coinsByParent",
                // `control.wallet.arrivals` (dig_ecosystem#2548) is NOT here, and the reasoning
                // that once put it here is the trap this test exists to spring. It is the
                // narrowest chain read on the list and still the only one that names an address
                // the CALLER did not: it takes a cursor and answers with this node's OWN watched
                // puzzle hashes. Public facts, private association.
                "control.wallet.peak",
                // `control.wallet.syncStatus` reports only how far THIS node has got.
                //
                // `control.peerCounts` is a DELIBERATE disclosure rather than an inert one, and
                // the distinction matters: its `dig_peer_count` is obtained by internally
                // dispatching `control.peerStatus`, which IS token-gated. What is opened is the
                // bare cardinality — how many peers this node holds — which a caller needs to
                // render a connection indicator and which reveals nothing about WHICH peers or
                // how they are reached. The identity/topology half of `peerStatus` stays behind
                // the token. Both are published open in `dig-node-control-interface`.
                "control.wallet.syncStatus",
                "control.peerCounts",
            ]
        );
        assert!(
            !is_open_control_read("control.wallet.broadcast"),
            "the push must stay behind the control token"
        );
        assert!(
            !is_open_control_read("control.wallet.arrivals"),
            "the arrival cursor names this node's own watched puzzle hashes to a caller that              supplied nothing, so it must stay behind the control token"
        );
    }

    /// **The reservation batch bound, pinned from BOTH sides (dig_ecosystem#3127, finding 1).**
    ///
    /// At the bound MUST pass and one over MUST fail. A bound asserted only from above can only
    /// confirm itself: it would pass identically for a cap of 1, which refuses every real spend.
    ///
    /// Scope, stated because it limits what this proves: it exercises the predicate, not the call
    /// site. The handler's use of it is three lines from its definition and is the only caller.
    #[test]
    fn the_reservation_batch_bound_admits_the_limit_and_refuses_one_over() {
        assert!(
            reserve_batch_refusal(MAX_RESERVE_COIN_IDS).is_none(),
            "a batch exactly at the bound is legitimate and must be admitted"
        );
        assert!(
            reserve_batch_refusal(MAX_RESERVE_COIN_IDS - 1).is_none(),
            "an ordinary batch under the bound must be admitted"
        );
        assert!(
            reserve_batch_refusal(0).is_none(),
            "an empty batch is a legitimate no-op, not an oversized one"
        );

        // The VALUE is pinned literally, not merely used symbolically. Every other assertion here
        // is written relative to the constant, so all of them pass for ANY value it holds --
        // including one so large the bound never fires. Measured: raising it to 1_000_000_000 was
        // caught by nothing until this line existed.
        assert_eq!(
            MAX_RESERVE_COIN_IDS, 1_000,
            "changing the bound is a deliberate act; justify it against the ceilings below"
        );

        let over = reserve_batch_refusal(MAX_RESERVE_COIN_IDS + 1)
            .expect("one id over the bound must be refused");
        assert!(
            over.contains(&(MAX_RESERVE_COIN_IDS + 1).to_string()),
            "the refusal must say how many were asked for, or a caller cannot size its retry: {over}"
        );
        assert!(
            over.contains(&MAX_RESERVE_COIN_IDS.to_string()),
            "the refusal must name the bound itself: {over}"
        );
    }

    /// The bound is a REFUSAL, never a silent truncation.
    ///
    /// Worth its own test because truncating is the tempting fix and it is the dangerous one: a
    /// caller handed a success for a batch the node only partly reserved believes it holds inputs
    /// it does not, which is the exact state all-or-none acquisition exists to make unreachable.
    #[test]
    fn an_oversized_batch_is_refused_rather_than_trimmed() {
        assert!(reserve_batch_refusal(MAX_RESERVE_COIN_IDS * 16).is_some());
    }

    /// **The watch methods stay GATED (§18.6f, #2823).**
    ///
    /// They aim this node's chain subscriptions, so they are mutations. Opening one would let any
    /// local process decide which addresses this machine associates itself with to its Chia peers.
    #[test]
    fn the_watch_methods_require_the_control_token() {
        for method in [
            "control.wallet.watch",
            "control.wallet.unwatch",
            "control.wallet.watched",
        ] {
            assert!(
                CONTROL_METHODS.contains(&method),
                "{method} must be a declared control method"
            );
            assert!(
                !is_open_control_read(method),
                "{method} aims this node's subscriptions and must stay behind the control token"
            );
        }
    }

    /// **A malformed key list registers NOTHING (§18.6f, #2823).**
    ///
    /// The fixture puts a VALID key beside the malformed one, which is what makes the test able to
    /// see the nearest wrong implementation — registering the entries that happened to parse. A
    /// partially-registered account is followed at fewer addresses than the client asked for, and
    /// that under-reports a balance quietly rather than failing visibly (dig_ecosystem#2762).
    #[test]
    fn a_malformed_key_refuses_the_whole_registration() {
        let valid = hex::encode(
            chia_bls::SecretKey::from_seed(&[7u8; 64])
                .public_key()
                .to_bytes(),
        );

        let err = parse_watch_keys(
            "control.wallet.watch",
            &json!(1),
            &json!({ "public_keys": [valid, "not-a-key"] }),
        )
        .expect_err("a malformed entry must refuse the request");

        assert_eq!(
            err["error"]["code"],
            json!(ErrorCode::InvalidParams.code()),
            "the refusal must be an invalid-params error, not a partial success"
        );
    }

    /// An empty list is refused rather than treated as a successful no-op, so a client that built
    /// its key list wrongly learns immediately instead of waiting for a balance that never arrives.
    #[test]
    fn an_empty_key_list_is_refused() {
        assert!(parse_watch_keys(
            "control.wallet.watch",
            &json!(1),
            &json!({ "public_keys": [] })
        )
        .is_err());
    }

    /// A well-formed list parses to exactly the keys given.
    #[test]
    fn a_well_formed_key_list_parses() {
        let keys: Vec<String> = [1u8, 2]
            .iter()
            .map(|t| {
                let mut seed = [0u8; 64];
                seed[0] = *t;
                hex::encode(
                    chia_bls::SecretKey::from_seed(&seed)
                        .public_key()
                        .to_bytes(),
                )
            })
            .collect();

        let parsed = parse_watch_keys(
            "control.wallet.watch",
            &json!(1),
            &json!({ "public_keys": keys }),
        )
        .expect("a well-formed list parses");

        assert_eq!(parsed.len(), 2);
    }

    /// `coins_wire` emits the contract shape: the requested asset echoed onto every coin, an
    /// explicitly-null `spent_height` (every coin here is unspent), and the tier fields.
    ///
    /// The two coins differ in `created_height` — one confirmed, one mempool-only — so a mapping
    /// that dropped or defaulted that field fails here rather than passing on a uniform fixture.
    #[test]
    fn coins_wire_emits_the_published_contract_shape() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::{WalletCoin, WalletCoinsResult};

        let wire = coins_wire(
            &WalletCoinsResult {
                coins: vec![
                    WalletCoin {
                        coin_id: "aa".repeat(32),
                        parent_coin_info: "bb".repeat(32),
                        puzzle_hash: "cc".repeat(32),
                        amount: 1_750_000_000_000,
                        created_height: Some(5_000_000),
                        spent_height: None,
                    },
                    WalletCoin {
                        coin_id: "dd".repeat(32),
                        parent_coin_info: "ee".repeat(32),
                        puzzle_hash: "cc".repeat(32),
                        amount: 7,
                        created_height: None,
                        spent_height: None,
                    },
                ],
                source: Source::Db,
                synced: true,
                peak_height: Some(5_000_000),
            },
            BalanceAsset::DIG,
        );

        assert_eq!(
            wire,
            json!({
                "coins": [
                    {
                        "coin_id": "aa".repeat(32), "asset": "dig", "amount": 1_750_000_000_000u64,
                        "parent_coin_info": "bb".repeat(32), "puzzle_hash": "cc".repeat(32),
                        "created_height": 5_000_000, "spent_height": null
                    },
                    {
                        "coin_id": "dd".repeat(32), "asset": "dig", "amount": 7,
                        "parent_coin_info": "ee".repeat(32), "puzzle_hash": "cc".repeat(32),
                        "created_height": null, "spent_height": null
                    }
                ],
                "source": "db", "synced": true, "peak_height": 5_000_000
            })
        );
    }

    /// **dig_ecosystem#3077 — the control plane accepts an ARBITRARY CAT and ECHOES it back.**
    ///
    /// Two properties in one test because they are one contract: the tagged request form must
    /// PARSE, and the answer must name the CAT it was scoped to rather than falling back to a
    /// token the node happens to know. The echo is the only place a caller can see WHICH asset the
    /// node read, so a `"dig"` or a `null` here would make an arbitrary-CAT read unverifiable.
    ///
    /// Uses a non-$DIG id deliberately: $DIG round-trips through a legacy token and so exercises
    /// neither the tagged parse nor the tagged emission.
    #[test]
    fn an_arbitrary_cat_parses_from_the_wire_and_is_echoed_onto_every_coin() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::{WalletCoin, WalletCoinsResult};

        let id = "11".repeat(32);
        let asset = parse_asset_param(
            "control.wallet.coins",
            &json!(1),
            &json!({ "address": "xch1…", "asset": { "cat": id } }),
        )
        .expect("the published tagged form parses");
        assert_ne!(asset, BalanceAsset::DIG, "a CAT that is not $DIG");

        let wire = coins_wire(
            &WalletCoinsResult {
                coins: vec![WalletCoin {
                    coin_id: "aa".repeat(32),
                    parent_coin_info: "bb".repeat(32),
                    puzzle_hash: "cc".repeat(32),
                    amount: 1,
                    created_height: Some(1),
                    spent_height: None,
                }],
                source: Source::Fallback,
                synced: false,
                peak_height: None,
            },
            asset,
        );
        assert_eq!(
            wire["coins"][0]["asset"],
            json!({ "cat": id }),
            "the coin names the CAT the read was scoped to"
        );
    }

    /// An `asset` that is PRESENT and names nothing is refused; an ABSENT one defaults to XCH.
    ///
    /// The pair matters more than either half. A parser that defaulted an unparseable asset to XCH
    /// would satisfy the absent case identically, and would turn a mistyped asset id into a
    /// confident balance for the wrong token — so the control is the omitted field, not a second
    /// bad value.
    #[test]
    fn an_unparseable_asset_is_refused_while_an_absent_one_defaults_to_xch() {
        for bad in [json!("dgi"), json!({ "cat": "nope" }), json!(7)] {
            assert!(
                parse_asset_param("m", &json!(1), &json!({ "asset": bad })).is_err(),
                "{bad} must not name an asset"
            );
        }
        assert_eq!(
            parse_asset_param("m", &json!(1), &json!({ "address": "xch1…" })),
            Ok(BalanceAsset::Xch),
            "an omitted asset is the documented XCH default"
        );
    }

    /// **`coins_wire` REPORTS a coin's `spent_height`; it does not assert one.**
    ///
    /// The mapper used to emit a hardcoded `null` here, justified by "every coin in an
    /// address-scoped read is unspent by construction". That was true of the CALLER, not of this
    /// function — the filtering lives at the read sites, two layers up. A literal in a mapper is a
    /// claim the mapper cannot check, and it silently outlives the invariant that motivated it.
    ///
    /// So this feeds `coins_wire` a SPENT coin, which the production callers never will, purely to
    /// prove the value travels. Reverting the mapper to a literal `null` fails this and nothing
    /// else — the two unspent-coin assertions above pass either way, which is exactly why they
    /// could not be left as the only coverage.
    #[test]
    fn coins_wire_reports_a_spent_height_rather_than_asserting_null() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::{WalletCoin, WalletCoinsResult};

        let wire = coins_wire(
            &WalletCoinsResult {
                coins: vec![WalletCoin {
                    coin_id: "aa".repeat(32),
                    parent_coin_info: "bb".repeat(32),
                    puzzle_hash: "cc".repeat(32),
                    amount: 1,
                    created_height: Some(5_000_000),
                    spent_height: Some(5_000_042),
                }],
                source: Source::Fallback,
                synced: false,
                peak_height: None,
            },
            BalanceAsset::Xch,
        );

        assert_eq!(
            wire["coins"][0]["spent_height"],
            json!(5_000_042),
            "the coin's own spent height reaches the wire; a hardcoded null would fail here"
        );
    }

    /// An address-less coin read is INVALID_PARAMS, and it names the parameter it wants.
    #[test]
    fn a_coin_read_without_an_address_is_invalid_params() {
        let response = wallet_address_params("control.wallet.coins", &json!(1), &json!({}))
            .expect_err("must refuse");
        assert_eq!(
            response["error"]["data"]["code"],
            json!(ErrorCode::InvalidParams.name())
        );
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("params.address"));
    }

    // ---- control.wallet.arrivals (dig_ecosystem#2548) --------------------------------------

    /// The amount reaches the wire as a STRING, and the asset id is carried verbatim for a CAT and
    /// `null` for XCH — never a ticker this node did not attribute.
    #[test]
    fn the_arrivals_wire_carries_amounts_as_strings_and_asset_ids_verbatim() {
        use dig_wallet::sage::arrivals::Arrival;
        let wire = arrivals_wire(
            0,
            &[
                Arrival {
                    seq: 7,
                    coin_id: "aa".repeat(32),
                    puzzle_hash: "cc".repeat(32),
                    // Beyond f64's exact-integer range: a JSON number would silently round it.
                    amount: "18446744073709551615".into(),
                    asset_id: None,
                    confirmed_height: 5_000_000,
                },
                Arrival {
                    seq: 8,
                    coin_id: "bb".repeat(32),
                    puzzle_hash: "dd".repeat(32),
                    amount: "1000".into(),
                    asset_id: Some("a406d3".into()),
                    confirmed_height: 5_000_001,
                },
            ],
            8,
        );
        assert_eq!(wire["arrivals"][0]["amount"], json!("18446744073709551615"));
        assert_eq!(wire["arrivals"][0]["asset_id"], Value::Null);
        assert_eq!(wire["arrivals"][0]["confirmed_height"], json!(5_000_000));
        assert_eq!(wire["arrivals"][1]["asset_id"], json!("a406d3"));
        assert_eq!(wire["cursor"], json!(8));
    }

    /// **The resume cursor is the last row HANDED OVER, never the ledger's newest position.**
    ///
    /// `latest` is read after the page, so an arrival recorded in between sits above the page and
    /// below `latest`. A client resuming from `latest` steps straight over it and the user is never
    /// told about that money — the one failure this whole method exists to prevent. Pinning the two
    /// fields apart is what stops a later "simplification" from collapsing them.
    #[test]
    fn the_resume_cursor_never_skips_past_an_arrival_the_client_was_not_given() {
        use dig_wallet::sage::arrivals::Arrival;
        let row = |seq: i64| Arrival {
            seq,
            coin_id: "aa".repeat(32),
            puzzle_hash: "cc".repeat(32),
            amount: "1".into(),
            asset_id: None,
            confirmed_height: 100,
        };
        // The page ends at 8; the ledger has since reached 12.
        let wire = arrivals_wire(0, &[row(7), row(8)], 12);
        assert_eq!(
            wire["cursor"],
            json!(8),
            "resuming from anything above 8 would silently drop arrivals 9..=12"
        );
        assert_eq!(wire["latest"], json!(12));
    }

    /// An empty page resumes from where the caller already was, and still reports `latest` so a
    /// first-run client can start from NOW instead of replaying the ledger as a burst of toasts.
    #[test]
    fn an_empty_arrivals_page_holds_the_cursor_and_still_reports_latest() {
        let wire = arrivals_wire(30, &[], 42);
        assert_eq!(wire["arrivals"], json!([]));
        assert_eq!(wire["cursor"], json!(30));
        assert_eq!(wire["latest"], json!(42));
    }

    /// The page size is caller-chosen on an OPEN, token-less method, so it is bounded on BOTH
    /// sides: a zero or negative limit cannot mean "no bound", and a huge one cannot mean "all".
    #[test]
    fn the_arrivals_page_size_is_clamped_at_both_ends() {
        assert_eq!(arrivals_limit(&json!({})), ARRIVALS_DEFAULT_LIMIT);
        assert_eq!(arrivals_limit(&json!({ "limit": 0 })), 1);
        assert_eq!(arrivals_limit(&json!({ "limit": -5 })), 1);
        assert_eq!(arrivals_limit(&json!({ "limit": 10 })), 10);
        assert_eq!(
            arrivals_limit(&json!({ "limit": 100_000 })),
            ARRIVALS_MAX_LIMIT
        );
        // A non-numeric limit falls back to the default rather than erroring the whole read.
        assert_eq!(
            arrivals_limit(&json!({ "limit": "all" })),
            ARRIVALS_DEFAULT_LIMIT
        );
    }

    // ---- control.wallet.coinById (dig_ecosystem#2392) --------------------------------------

    /// Assert one `coin_id` spelling is REFUSED as `INVALID_PARAMS` naming the parameter.
    ///
    /// Both halves matter: the code alone would also be produced by a handler that wanted
    /// different params entirely, and the message is what tells a caller WHICH argument it got
    /// wrong.
    fn assert_coin_id_refused(params: Value, why: &str) {
        let response = wallet_coin_id_param(&json!(1), &params)
            .expect_err(&format!("must refuse {why}: {params}"));
        assert_eq!(
            response["error"]["data"]["code"],
            json!(ErrorCode::InvalidParams.name()),
            "{why} must be INVALID_PARAMS: {response:?}"
        );
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("coin_id"),
            "{why}: the refusal must name coin_id: {response:?}"
        );
    }

    /// **Proves:** every malformed `coin_id` spelling is refused, naming the parameter.
    ///
    /// **Catches** a validator that accepts anything string-shaped and forwards it to the chain
    /// oracle. The two length cases are 63 and 65 hex characters — the exact off-by-one
    /// neighbours of the 64-character contract — so a `>= 64`, `<= 64` or `!= 63` length check
    /// fails here rather than passing on a wildly-wrong fixture. `"zz".repeat(32)` is the RIGHT
    /// length and the wrong alphabet, which isolates the alphabet check from the length check;
    /// without it, a validator that only measured length would pass every other case.
    #[test]
    fn a_malformed_coin_id_is_refused_before_anything_else() {
        assert_coin_id_refused(json!({}), "a missing coin_id");
        assert_coin_id_refused(json!({ "coin_id": 12345 }), "a non-string coin_id");
        assert_coin_id_refused(json!({ "coin_id": "" }), "an empty coin_id");
        assert_coin_id_refused(json!({ "coin_id": "a".repeat(63) }), "63 hex characters");
        assert_coin_id_refused(json!({ "coin_id": "a".repeat(65) }), "65 hex characters");
        assert_coin_id_refused(
            json!({ "coin_id": "zz".repeat(32) }),
            "64 NON-hex characters",
        );
        // `0x` + 63 hex is 65 characters of input and 63 of id: the length must be measured
        // AFTER the prefix is stripped, or the prefix silently buys a character of slack.
        assert_coin_id_refused(
            json!({ "coin_id": format!("0x{}", "a".repeat(63)) }),
            "a 0x prefix over 63 hex characters",
        );
    }

    /// **Proves:** UPPERCASE hex is REFUSED, not silently lowercased.
    ///
    /// Its own test because it is the one refusal a reviewer is most likely to read as a bug and
    /// "fix" into a normalization. The contract accepts exactly one spelling of a coin id (see
    /// [`wallet_coin_id_param`]'s doc comment), so a node that lowercased would accept ids a
    /// conforming implementation rejects, and a caller built against this node would break
    /// against any other. **Catches** exactly that leniency: adding `.to_ascii_lowercase()` to
    /// the validator fails here and nowhere else.
    #[test]
    fn an_uppercase_coin_id_is_refused_rather_than_normalized() {
        assert_coin_id_refused(json!({ "coin_id": "A".repeat(64) }), "all-uppercase hex");
        // One uppercase character in an otherwise-valid id — the case a per-character check with
        // an accidentally case-insensitive comparison would let through.
        let mut mixed = "a".repeat(63);
        mixed.push('B');
        assert_coin_id_refused(json!({ "coin_id": mixed }), "a single uppercase character");
    }

    /// **Proves:** a well-formed id is accepted and returned in the canonical BARE lowercase
    /// form, with an optional `0x` prefix stripped.
    ///
    /// **Catches** a validator that returns the caller's raw string. Both spellings must map to
    /// the SAME output — if the prefixed form came back with its prefix, the node would send two
    /// different strings to the oracle for one coin, and a caller polling a spend would see one
    /// of them answer `coin: null` forever.
    #[test]
    fn a_well_formed_coin_id_is_accepted_bare_and_lowercase() {
        let bare = "ab".repeat(32);
        assert_eq!(
            wallet_coin_id_param(&json!(1), &json!({ "coin_id": bare.clone() })).unwrap(),
            bare,
            "a bare id must come back unchanged"
        );
        assert_eq!(
            wallet_coin_id_param(&json!(1), &json!({ "coin_id": format!("0x{bare}") })).unwrap(),
            bare,
            "the 0x prefix must be stripped, yielding the identical bare id"
        );
    }

    /// **Proves:** `coin_by_id_wire` emits the published contract shape for a FOUND coin,
    /// carrying both heights.
    ///
    /// The fixture is a coin that is created AND spent, at two different heights, on the fallback
    /// tier with an unknown peak — the shape a mint poll actually observes once its funding coin
    /// is gone. **Catches** a mapper that drops `spent_height`, defaults either height, or
    /// renames a field: every field is pinned by whole-value equality, so an added or missing
    /// member fails too.
    #[test]
    fn coin_by_id_wire_emits_the_published_contract_shape() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::{WalletCoin, WalletCoinByIdResult};

        let wire = coin_by_id_wire(&WalletCoinByIdResult {
            coin: Some(WalletCoin {
                coin_id: "aa".repeat(32),
                parent_coin_info: "bb".repeat(32),
                puzzle_hash: "cc".repeat(32),
                amount: 1_000_000_000_000,
                created_height: Some(5_000_000),
                spent_height: Some(5_000_042),
            }),
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        });

        assert_eq!(
            wire,
            json!({
                "coin": {
                    "coin_id": "aa".repeat(32),
                    "asset": null,
                    "amount": 1_000_000_000_000u64,
                    "parent_coin_info": "bb".repeat(32),
                    "puzzle_hash": "cc".repeat(32),
                    "created_height": 5_000_000,
                    "spent_height": 5_000_042
                },
                "source": "fallback",
                "synced": false,
                "peak_height": null
            })
        );
    }

    /// **Proves:** `asset` on a by-id coin is ALWAYS `null`, whatever the coin looks like.
    ///
    /// Its own test because the whole-shape test above could pass on a mapper that guessed an
    /// asset and happened to guess `null` for that one fixture. A coin id alone does not reveal
    /// whether the coin is XCH, a CAT or a singleton — that needs the puzzle, which this read
    /// never inspects — so any non-null value here is a classification the node did not verify.
    ///
    /// **Catches** the tempting copy-paste from [`coins_wire`], which echoes the REQUESTED asset:
    /// there is no requested asset here, so such a mapper would have to invent one (`"xch"` being
    /// the obvious default), and inventing anything fails here.
    #[test]
    fn coin_by_id_wire_never_names_an_asset_it_did_not_verify() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::{WalletCoin, WalletCoinByIdResult};

        // A CAT-sized amount on a synced DB-tier answer: deliberately the case most likely to
        // tempt a classification, and the opposite tier/sync combination to the test above.
        let wire = coin_by_id_wire(&WalletCoinByIdResult {
            coin: Some(WalletCoin {
                coin_id: "11".repeat(32),
                parent_coin_info: "22".repeat(32),
                puzzle_hash: "33".repeat(32),
                amount: 1_000,
                created_height: Some(1),
                spent_height: None,
            }),
            source: Source::Db,
            synced: true,
            peak_height: Some(6_000_000),
        });

        assert_eq!(
            wire["coin"]["asset"],
            Value::Null,
            "a by-id read must not name an asset: {wire}"
        );
        // The tier fields still travel, so this fixture is not passing merely by being empty.
        assert_eq!(wire["source"], json!("db"));
        assert_eq!(wire["synced"], json!(true));
        assert_eq!(wire["peak_height"], json!(6_000_000));
        assert_eq!(wire["coin"]["spent_height"], Value::Null);
    }

    /// **Proves:** an ABSENT coin is a SUCCESS carrying `coin: null` — a `result` member, never an
    /// `error` member.
    ///
    /// This distinction is the entire point of dig_ecosystem#2392. "The chain was consulted and
    /// has no such coin" and "no chain could be consulted" are opposite facts with opposite
    /// remedies: a mint poll that reads the first as the second reports a failed mint on a
    /// dropped connection, and one that reads the second as the first declares a mint missing
    /// that is merely unobserved.
    ///
    /// **Catches** a handler that mapped `None` onto a catalogued error. Asserting only
    /// `wire["coin"] == null` would NOT catch it — a JSON-RPC error response has no `coin` member
    /// at all, so that lookup is also `null`. Hence the assertion is on the RESPONSE envelope:
    /// `result` present, `error` absent.
    #[test]
    fn an_absent_coin_is_a_result_carrying_null_not_an_error() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::WalletCoinByIdResult;

        let wire = coin_by_id_wire(&WalletCoinByIdResult {
            coin: None,
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        });
        assert_eq!(
            wire,
            json!({
                "coin": null,
                "source": "fallback",
                "synced": false,
                "peak_height": null
            })
        );

        // The envelope the handler actually returns for this mapping.
        let response = control_ok(json!(7), wire);
        assert!(
            response.get("result").is_some(),
            "an absent coin must answer with a result member: {response:?}"
        );
        assert!(
            response.get("error").is_none(),
            "an absent coin must NOT be an error: {response:?}"
        );
        assert_eq!(response["result"]["coin"], Value::Null);
    }

    // ---- control.wallet.coinSpend + coinsByParent wire shapes (dig_ecosystem#2572) ----

    fn a_spent_coin() -> dig_wallet::sage::rpc::WalletCoin {
        dig_wallet::sage::rpc::WalletCoin {
            coin_id: "aa".repeat(32),
            parent_coin_info: "bb".repeat(32),
            puzzle_hash: "cc".repeat(32),
            amount: 1_000_000_000_000,
            created_height: Some(5_000_000),
            spent_height: Some(5_000_042),
        }
    }

    /// **Proves:** `coin_spend_wire` emits the published contract shape for a FOUND spend.
    ///
    /// Pinned by whole-value equality, so a renamed, added or dropped member fails — including the
    /// `solution`, the one field with no verification attached to it and therefore the easy one to
    /// lose. The coin's `spent_height` is non-null in the fixture because the contract requires it:
    /// a spend of a coin nothing calls spent is a contradiction.
    #[test]
    fn coin_spend_wire_emits_the_published_contract_shape() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::{WalletCoinSpend, WalletCoinSpendResult};

        let wire = coin_spend_wire(&WalletCoinSpendResult {
            spend: Some(WalletCoinSpend {
                coin: a_spent_coin(),
                puzzle_reveal: "ff0180".to_string(),
                solution: "80".to_string(),
            }),
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        });

        assert_eq!(
            wire,
            json!({
                "spend": {
                    "coin": {
                        "coin_id": "aa".repeat(32),
                        "asset": null,
                        "amount": 1_000_000_000_000u64,
                        "parent_coin_info": "bb".repeat(32),
                        "puzzle_hash": "cc".repeat(32),
                        "created_height": 5_000_000,
                        "spent_height": 5_000_042
                    },
                    "puzzle_reveal": "ff0180",
                    "solution": "80"
                },
                "source": "fallback",
                "synced": false,
                "peak_height": null
            })
        );
    }

    /// **Proves:** an ABSENT spend is a SUCCESS carrying `spend: null` — a `result` member, never
    /// an `error` member.
    ///
    /// The same distinction `an_absent_coin_is_a_result_carrying_null_not_an_error` pins for
    /// `coinById`, on the read where collapsing it is worse: `spend: null` tells a caller the coin
    /// is still unspent, which is the go-ahead to spend it, so an outage wearing that shape invites
    /// a double-spend.
    ///
    /// **Catches** a handler that mapped `None` onto a catalogued error. Asserting only
    /// `wire["spend"] == null` would NOT catch it — a JSON-RPC error response has no `spend` member
    /// at all, so that lookup is `null` too. Hence the assertion is on the ENVELOPE.
    #[test]
    fn an_absent_spend_is_a_result_carrying_null_not_an_error() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::WalletCoinSpendResult;

        let wire = coin_spend_wire(&WalletCoinSpendResult {
            spend: None,
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        });
        assert_eq!(
            wire,
            json!({
                "spend": null,
                "source": "fallback",
                "synced": false,
                "peak_height": null
            })
        );

        let response = control_ok(json!(7), wire);
        assert!(
            response.get("result").is_some(),
            "an absent spend must answer with a result member: {response:?}"
        );
        assert!(
            response.get("error").is_none(),
            "an absent spend must NOT be an error: {response:?}"
        );
    }

    /// **Proves:** `coins_by_parent_wire` emits the paged contract shape, `complete` and `cursor`
    /// included.
    ///
    /// **Catches** a mapper that emitted only the coin list. A client decodes `complete` as a plain
    /// `bool` (no serde default) and `cursor` with `required_option`, so an omitted member is a hard
    /// decode error rather than a silent default — but the failure would then surface on the CLIENT,
    /// on a live node, rather than here.
    #[test]
    fn coins_by_parent_wire_emits_the_paged_contract_shape() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::WalletCoinsByParentResult;

        let wire = coins_by_parent_wire(&WalletCoinsByParentResult {
            coins: vec![a_spent_coin()],
            complete: false,
            cursor: Some("aa".repeat(32)),
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        });

        assert_eq!(
            wire,
            json!({
                "coins": [{
                    "coin_id": "aa".repeat(32),
                    "asset": null,
                    "amount": 1_000_000_000_000u64,
                    "parent_coin_info": "bb".repeat(32),
                    "puzzle_hash": "cc".repeat(32),
                    "created_height": 5_000_000,
                    "spent_height": 5_000_042
                }],
                "complete": false,
                "cursor": "aa".repeat(32),
                "source": "fallback",
                "synced": false,
                "peak_height": null
            })
        );
    }

    /// **Proves:** an empty page still carries both paging members, with `cursor: null`.
    ///
    /// Its own test because the shape above is non-empty, and the empty page is where a mapper is
    /// most likely to omit `cursor` (there is nothing to put in it) — which on the client decodes as
    /// an error rather than as "nothing to resume from". `complete: true` here is what tells a
    /// lineage walker the branch genuinely ends.
    #[test]
    fn an_empty_child_page_still_carries_complete_and_a_null_cursor() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::WalletCoinsByParentResult;

        let wire = coins_by_parent_wire(&WalletCoinsByParentResult {
            coins: vec![],
            complete: true,
            cursor: None,
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        });

        assert_eq!(
            wire,
            json!({
                "coins": [],
                "complete": true,
                "cursor": null,
                "source": "fallback",
                "synced": false,
                "peak_height": null
            })
        );
    }

    /// **Proves:** neither new read names an asset it did not verify.
    ///
    /// A coin id and a parent id both classify nothing — telling XCH from a CAT from a singleton
    /// needs the puzzle, which neither read inspects. **Catches** the tempting copy-paste from
    /// [`coins_wire`], which echoes the REQUESTED asset: there is no requested asset on either of
    /// these, so such a mapper has to invent one (`"xch"` being the obvious guess).
    #[test]
    fn neither_new_read_names_an_asset_it_did_not_verify() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::{
            WalletCoinSpend, WalletCoinSpendResult, WalletCoinsByParentResult,
        };

        let spend = coin_spend_wire(&WalletCoinSpendResult {
            spend: Some(WalletCoinSpend {
                coin: a_spent_coin(),
                puzzle_reveal: "01".into(),
                solution: "80".into(),
            }),
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        });
        assert_eq!(spend["spend"]["coin"]["asset"], Value::Null);

        let children = coins_by_parent_wire(&WalletCoinsByParentResult {
            coins: vec![a_spent_coin()],
            complete: true,
            cursor: Some("aa".repeat(32)),
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        });
        assert_eq!(children["coins"][0]["asset"], Value::Null);
    }

    /// **Proves:** the page bound is refused from BOTH sides — at-bound passes, one over fails, and
    /// zero fails.
    ///
    /// A bound tested only from below can only confirm itself. `1000` is the contract's maximum and
    /// MUST be accepted; `1001` and `0` MUST be refused rather than clamped, because this read's
    /// page boundary is what the caller resumes from — a silently shrunk page hands back a cursor
    /// for a position the caller never asked about, and a `limit: 0` page makes no progress, so a
    /// caller looping until a short page arrives loops forever.
    #[test]
    fn the_page_bound_is_enforced_from_both_sides_and_never_clamped() {
        let parent = "ab".repeat(32);
        let with_limit = |limit: Value| {
            wallet_coins_by_parent_params(
                &json!(1),
                &json!({ "parent_coin_id": parent, "limit": limit }),
            )
        };

        assert_eq!(
            with_limit(json!(1000)).expect("the maximum is legal").limit,
            Some(1000)
        );
        assert!(with_limit(json!(1001)).is_err(), "one over must be refused");
        assert!(
            with_limit(json!(0)).is_err(),
            "a page of zero makes no progress"
        );

        // Omitted resolves to the CONTRACT's default, not a number this node invented — so a node
        // and a client can never disagree about where an unspecified page ends.
        let defaulted =
            wallet_coins_by_parent_params(&json!(1), &json!({ "parent_coin_id": parent }))
                .expect("an omitted limit is legal");
        assert_eq!(defaulted.limit, None);
        assert_eq!(
            defaulted.effective_limit(),
            dig_node_control_interface::params::COINS_BY_PARENT_DEFAULT_LIMIT
        );
    }

    /// **Proves:** a malformed resume cursor is REFUSED, never treated as "start from the
    /// beginning".
    ///
    /// The dangerous default. A caller that sent a bad `after_coin_id` and got page one back would
    /// re-walk children it had already processed, and — since the answer looks like a perfectly
    /// normal page — would never learn it had restarted. The well-formed control alongside it is
    /// what proves the refusal comes from the cursor's spelling rather than from the field being
    /// present at all.
    #[test]
    fn a_malformed_resume_cursor_is_refused_not_silently_ignored() {
        let parent = "ab".repeat(32);
        let with_cursor = |cursor: &str| {
            wallet_coins_by_parent_params(
                &json!(1),
                &json!({ "parent_coin_id": parent, "after_coin_id": cursor }),
            )
        };

        assert!(
            with_cursor(&"a".repeat(63)).is_err(),
            "a 63-hex cursor must be refused, not dropped"
        );
        assert!(
            with_cursor(&"AB".repeat(32)).is_err(),
            "uppercase is refused, exactly as it is for a coin id"
        );
        assert_eq!(
            with_cursor(&format!("0x{}", "cd".repeat(32)))
                .expect("a 0x-prefixed cursor is legal")
                .after_coin_id
                .as_deref(),
            Some("cd".repeat(32).as_str()),
            "the 0x prefix is stripped, never emitted"
        );
    }

    /// The five light-client CHAIN READS the dig-app and `dign` depend on (dig_ecosystem#1701).
    ///
    /// Named individually rather than by prefix because the carve-out that removed node-side USER
    /// custody had to leave EXACTLY these untouched, and a prefix check would keep passing if four
    /// of the five were dropped.
    const LIGHT_CLIENT_READS: [&str; 5] = [
        "control.wallet.balance",
        "control.wallet.coins",
        "control.wallet.peak",
        "control.wallet.syncStatus",
        "control.wallet.broadcast",
    ];

    /// **Proves (dig_ecosystem#1701, step 4):** removing node-side USER custody left the light
    /// client served.
    ///
    /// Two facts, and both are needed. Membership in `CONTROL_METHODS` is what makes a method
    /// DISCOVERABLE; membership in `OWNED_CONTROL_METHODS` is what routes it to a real arm of
    /// `dispatch_owned` — whose `_` arm is `unreachable!()` by construction, so
    /// `control_methods_partition_into_owned_and_delegated` below turns red if any owned name lost
    /// its handler. Asserting discovery alone would pass over a method that resolves to nothing.
    #[test]
    fn the_light_client_chain_reads_survive_the_custody_carve_out() {
        for m in LIGHT_CLIENT_READS {
            assert!(
                CONTROL_METHODS.contains(&m),
                "{m} left the published control surface - the light client cannot find it"
            );
            assert!(
                OWNED_CONTROL_METHODS.contains(&m),
                "{m} is published but no longer routed to a handler in this shell"
            );
        }
    }

    /// **Proves the guard above is not blind to a removal**, by checking a name that is genuinely
    /// absent behaves the way a dropped read would.
    ///
    /// Without this, `LIGHT_CLIENT_READS` could be quietly emptied or misspelled and the loop would
    /// iterate over nothing (or over names no list was ever meant to hold) while reporting success.
    #[test]
    fn the_light_client_guard_would_notice_a_missing_read() {
        assert_eq!(LIGHT_CLIENT_READS.len(), 5, "the guard must check all five");
        assert!(
            !CONTROL_METHODS.contains(&"control.wallet.aReadThatDoesNotExist"),
            "the haystack must not contain arbitrary names, or the guard proves nothing"
        );
    }

    /// LOCKSTEP GATE (#711): [`dispatch_control`] resolves EXACTLY [`CONTROL_METHODS`] — the
    /// owned set it routes to `dispatch_owned` ([`OWNED_CONTROL_METHODS`]) plus the set it
    /// delegates to the node ([`DELEGATED_CONTROL_METHODS`]) — the two disjoint, and their union
    /// equal to the declared surface. This closes the shell-owned-method drift gap the CLI-parity
    /// test (`cli_covers_every_node_control_method`) leaves open: a `dispatch_owned` arm added
    /// without declaring it (in `OWNED_CONTROL_METHODS` + `CONTROL_METHODS`) fails HERE, and a
    /// declared owned method with no arm makes `dispatch_owned`'s `unreachable!` fire.
    #[test]
    fn control_methods_partition_into_owned_and_delegated() {
        use std::collections::BTreeSet;
        let listed: BTreeSet<&str> = CONTROL_METHODS.iter().copied().collect();
        let owned: BTreeSet<&str> = OWNED_CONTROL_METHODS.iter().copied().collect();
        let delegated: BTreeSet<&str> = DELEGATED_CONTROL_METHODS.iter().copied().collect();

        // Each list is duplicate-free.
        assert_eq!(
            owned.len(),
            OWNED_CONTROL_METHODS.len(),
            "OWNED has duplicates"
        );
        assert_eq!(
            delegated.len(),
            DELEGATED_CONTROL_METHODS.len(),
            "DELEGATED has duplicates"
        );
        assert_eq!(
            listed.len(),
            CONTROL_METHODS.len(),
            "CONTROL_METHODS has duplicates"
        );

        // Owned and delegated are disjoint — no method is both handled and forwarded.
        let both: Vec<&&str> = owned.intersection(&delegated).collect();
        assert!(
            both.is_empty(),
            "methods both owned AND delegated: {both:?}"
        );

        // The union is EXACTLY the declared surface — neither an undeclared handler nor a
        // declared-but-unhandled method can slip through.
        let union: BTreeSet<&str> = owned.union(&delegated).copied().collect();
        assert_eq!(
            listed, union,
            "CONTROL_METHODS drifted from dispatch_control's owned+delegated set"
        );
    }

    /// LOCKSTEP GATE (#254): the methods this node reserves for the MASTER token are EXACTLY the
    /// methods the contract puts on the master tier.
    ///
    /// This test exists because the two sets already diverged once, silently and in the
    /// fail-OPEN direction. [`requires_master_token`] used to restate the tier as a match on three
    /// pairing strings; when the contract moved `chiaPeers.add`/`.remove` to the master tier this
    /// node went on honouring the old list, so a PAIRED token could install a Chia peer that is
    /// believed without corroboration and keeps that authority after `pairing.revoke`.
    ///
    /// The expectation is written out by NAME rather than derived from the predicate under test:
    /// a derivation would agree with any implementation, including the one this test was written
    /// to catch. Reverting to the three-string list drops the two `chiaPeers` entries from
    /// `actual` and fails on the first assertion, naming them.
    #[test]
    fn master_token_set_matches_the_contract() {
        use std::collections::BTreeSet;

        let actual: BTreeSet<&str> = CONTROL_METHODS
            .iter()
            .copied()
            .filter(|m| requires_master_token(m))
            .collect();

        let expected: BTreeSet<&str> = [
            "control.pairing.list",
            "control.pairing.approve",
            "control.pairing.revoke",
            "control.chiaPeers.add",
            "control.chiaPeers.remove",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            actual, expected,
            "the master-token tier drifted from the set this node means to reserve"
        );

        // And it tracks the CONTRACT, so a method the contract promotes later cannot stay
        // paired-reachable here just because nobody edited the list above.
        let contract: BTreeSet<&str> = ControlMethod::ALL
            .iter()
            .filter(|m| m.requires_master_token())
            .map(|m| m.name())
            .filter(|n| CONTROL_METHODS.contains(n))
            .collect();
        assert_eq!(
            actual, contract,
            "this node's master tier disagrees with dig-node-control-interface"
        );
    }

    /// The tier is per-METHOD, never per-namespace: `chiaPeers.list` stays on the ordinary tier.
    ///
    /// The control that keeps [`master_token_set_matches_the_contract`] honest. Gating the whole
    /// `chiaPeers.*` namespace would also close the escalation, and would ALSO leave a paired
    /// client unable to show the operator which peers their node trusts — the one disclosure that
    /// makes the trust state correctable. A read grants nothing that outlives the token, so it is
    /// not on the master tier and this test fails if a namespace-shaped fix is substituted.
    #[test]
    fn reading_the_trusted_peer_list_is_not_master_tier() {
        assert!(requires_master_token("control.chiaPeers.add"));
        assert!(requires_master_token("control.chiaPeers.remove"));
        assert!(
            !requires_master_token("control.chiaPeers.list"),
            "a paired client must still be able to SHOW the operator the trust state"
        );
    }

    /// **The trust wording stays inside NC-12's authorisation: a node the operator RUNS (#254).**
    ///
    /// NC-12 permits trust only from the operator declaring a node THEIR OWN, and that is what
    /// justifies the unbounded authority the entry carries. Widening it to vouching moves the case
    /// outside the justification — and "a node you vouch for" is a phrase somebody can be talked
    /// into applying to a stranger's address, which is precisely how a social-engineering path
    /// into the wallet replica opens.
    ///
    /// The banned list mirrors the contract's own wording test, so the node and the published
    /// method summary cannot drift into disagreeing about what the operator is being asked to
    /// certify. The CLI help carries the same sentence and is checked in `entrypoint`.
    #[test]
    fn the_trust_wording_authorises_only_a_node_the_operator_runs() {
        let notice = CORROBORATION_BYPASS_NOTICE.to_lowercase();
        assert!(
            notice.contains("a node you run yourself"),
            "the notice must name the operator-run scope, got: {notice}"
        );
        assert!(
            notice.contains("corroboration"),
            "the notice must name the cost it exists to disclose, got: {notice}"
        );
        for widened in ["vouch", "otherwise trust", "trust yourself", "recommend"] {
            assert!(
                !notice.contains(widened),
                "the notice widens operator trust past NC-12 with {widened:?}: {notice}"
            );
        }

        // The un-banned-without-trust notice must NOT imply a bypass it did not grant.
        let unbanned = UNBANNED_WITHOUT_TRUST_NOTICE.to_lowercase();
        assert!(
            unbanned.contains("not granted trust") && unbanned.contains("still"),
            "the person must be told what actually happened, got: {unbanned}"
        );
        assert!(
            !unbanned.contains("is now trusted"),
            "un-banning grants no trust and must not claim it: {unbanned}"
        );
    }

    /// A `control.*` name this node does not serve fails CLOSED — master token required.
    ///
    /// [`is_control_method`] gates on the prefix alone, so these names DO reach the predicate.
    /// The served-but-unpublished diagnostic is the deliberate exception, named in
    /// [`KNOWN_UNPUBLISHED_CONTROL_METHODS`] and asserted here beside them.
    #[test]
    fn an_unserved_control_method_requires_the_master_token() {
        assert!(requires_master_token("control.notAThing"));
        assert!(requires_master_token("control.chiaPeers.addd"));
        assert!(
            !requires_master_token("control.peers.ping"),
            "a served diagnostic keeps the ordinary tier until the contract publishes it"
        );
    }

    /// **A served-but-unpublished method is master-tier unless it is NAMED as the exception.**
    ///
    /// This is the assertion the old carve-out could not make. When the exemption was "in
    /// `CONTROL_METHODS` but unknown to the contract", adding a method to the served list made it
    /// paired-reachable on the spot, and every lockstep test stayed green — a method the contract
    /// does not publish is absent from BOTH sides of the set comparisons they perform, so it is not
    /// tested loosely, it is not tested at all.
    ///
    /// The fixture must be a name this node SERVES, because that is the only input on which the
    /// two carve-outs disagree: a merely-unknown name answers "master" under both, so a test using
    /// one cannot fail on the difference. `control.peers.ping` is the one served-but-unpublished
    /// method that exists, so it is asserted twice — once WITHOUT the exemption (must be master
    /// tier: serving a method grants it nothing) and once WITH it (ordinary, as the allowlist says).
    #[test]
    fn a_served_but_unpublished_method_is_not_exempt_unless_it_is_named() {
        let served_unpublished = "control.peers.ping";
        assert!(
            ControlMethod::from_name(served_unpublished).is_none()
                && CONTROL_METHODS.contains(&served_unpublished),
            "fixture drift: {served_unpublished} must be served here and unpublished by the contract"
        );

        assert!(
            requires_master_token_given(served_unpublished, &[]),
            "being SERVED must grant no exemption: an unpublished method fails CLOSED unless it is \
             named in KNOWN_UNPUBLISHED_CONTROL_METHODS, so a future method cannot inherit the \
             ordinary tier as a side effect of being added to CONTROL_METHODS"
        );
        assert!(
            !requires_master_token_given(served_unpublished, KNOWN_UNPUBLISHED_CONTROL_METHODS),
            "the named exception keeps the ordinary tier"
        );

        // And the production predicate agrees with the named-exception arm.
        for exempt in KNOWN_UNPUBLISHED_CONTROL_METHODS {
            assert!(!requires_master_token(exempt), "{exempt}");
        }
    }

    /// The control boundary reports an UNOBSERVED peak as `null` and an observed one verbatim.
    ///
    /// Both directions matter and only one of them is the fix: asserting `null` for `0` alone would
    /// also pass if the field were hard-wired to `null`, which would hide every real height the
    /// moment telemetry lands. The observed case is the control that rules that out.
    #[test]
    fn the_control_list_reports_an_unpolled_peak_as_null_and_a_real_one_verbatim() {
        let peer = |peak: u32| dig_wallet::sage::types::PeerRecord {
            ip_addr: "1.2.3.4".into(),
            port: 8444,
            peak_height: peak,
            user_managed: true,
            banned: false,
        };

        let unpolled = chia_peer_wire(&peer(0));
        assert_eq!(
            unpolled["peak_height"],
            json!(null),
            "a peer nobody has polled must not read as one stalled at genesis: {unpolled}"
        );

        let observed = chia_peer_wire(&peer(6_000_000));
        assert_eq!(observed["peak_height"], json!(6_000_000));
        assert_eq!(observed["ip"], json!("1.2.3.4"));
        assert_eq!(observed["banned"], json!(false));
    }

    #[test]
    fn is_control_method_only_matches_control_namespace() {
        assert!(is_control_method("control.status"));
        assert!(is_control_method("control.hostedStores.pin"));
        assert!(!is_control_method("dig.getContent"));
        assert!(!is_control_method("cache.getConfig"));
        assert!(!is_control_method("rpc.discover"));
        assert!(!is_control_method(""));
    }

    #[test]
    fn read_methods_are_always_authorized_without_a_token() {
        // The whole point of the gate: read methods are open to local consumers.
        assert!(is_authorized("dig.getContent", None, "secret"));
        assert!(is_authorized("cache.getConfig", None, "secret"));
        assert!(is_authorized("rpc.discover", None, "secret"));
    }

    #[test]
    fn control_method_without_token_is_rejected() {
        assert!(!is_authorized("control.status", None, "secret"));
    }

    #[test]
    fn control_method_with_wrong_token_is_rejected() {
        assert!(!is_authorized("control.status", Some("wrong"), "secret"));
    }

    #[test]
    fn control_method_with_correct_token_is_allowed() {
        assert!(is_authorized("control.status", Some("secret"), "secret"));
    }

    /// Fail-closed regression: when the configured token is the EMPTY fail-closed
    /// sentinel (CSPRNG mint/persist failure → empty in-memory token), NO presented
    /// token authorizes a `control.*` method — not even a blank one, which `ct_eq`
    /// would otherwise match against a blank expected. The empty sentinel is never a
    /// usable credential (§7.3).
    #[test]
    fn empty_expected_token_authorizes_nothing() {
        assert!(!is_authorized("control.status", Some(""), ""));
        assert!(!is_authorized("control.status", Some("anything"), ""));
        assert!(!is_authorized("control.status", None, ""));
        // A healthy 64-hex token still authorizes its exact match (no regression).
        assert!(is_authorized("control.status", Some("secret"), "secret"));
    }

    #[test]
    fn log_set_level_rejects_a_missing_filter_param() {
        // #553: `control.log.setLevel` needs `params.filter`; an empty body is an InvalidParams
        // error, never a silent no-op.
        let resp = log_set_level(json!(1), &json!({}));
        assert_eq!(
            resp["error"]["code"],
            json!(ErrorCode::InvalidParams.code())
        );
    }

    #[test]
    fn log_set_level_errors_when_logging_is_not_installed() {
        // #553: in a plain `cargo test` process no serve path installed the logging guard, so a
        // live level change reports a ControlError (rather than pretending it applied). A valid
        // directive still parses — the failure is specifically "logging not initialised".
        let resp = log_set_level(json!(1), &json!({ "filter": "debug" }));
        assert_eq!(resp["error"]["code"], json!(ErrorCode::ControlError.code()));
    }

    #[test]
    fn ct_eq_matches_string_equality_but_constant_time() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd")); // length differs
        assert!(!ct_eq("", "x"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn presented_token_prefers_header_then_param() {
        let req = json!({ "params": { "_control_token": "from-param" } });
        assert_eq!(
            presented_token(Some("from-header"), &req),
            Some("from-header".to_string())
        );
        assert_eq!(presented_token(None, &req), Some("from-param".to_string()));
        assert_eq!(
            presented_token(Some("   "), &req),
            Some("from-param".to_string())
        );
        assert_eq!(presented_token(None, &json!({})), None);
    }

    #[test]
    fn generate_token_is_64_hex_and_unique() {
        let a = generate_token().expect("OS CSPRNG available in tests");
        let b = generate_token().expect("OS CSPRNG available in tests");
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two generated tokens must differ");
    }

    /// The control token must NOT be reproducible from a fixed process context. Before
    /// the CSPRNG fix, `fill_random` fell back on Windows/`/dev/urandom`-less hosts to a
    /// splitmix64 stream seeded purely from `nanos ^ pid ^ stack_addr` — an attacker who
    /// estimated the mint time/PID/ASLR could reconstruct the whole control-plane token.
    /// That deterministic seed path is now gone: every byte comes from the OS CSPRNG.
    ///
    /// HONEST LIMIT: this test cannot validate randomness QUALITY (no unit test can —
    /// that needs statistical/known-answer suites the OS CSPRNG already carries). It only
    /// asserts the seed-determinism escape hatch is gone: within one process (fixed PID,
    /// near-fixed time) many draws are all distinct, which the old seeded stream — a pure
    /// function of that fixed context per call site — could not guarantee across calls
    /// the way an independent CSPRNG draw does.
    #[test]
    fn random_hex_is_not_reproducible_from_fixed_process_context() {
        let draws: std::collections::HashSet<String> = (0..64)
            .map(|_| random_hex(32).expect("OS CSPRNG available in tests"))
            .collect();
        assert_eq!(
            draws.len(),
            64,
            "64 tokens drawn in one process (fixed pid/time) must all differ — no \
             deterministic seed path remains"
        );
    }

    /// Fail CLOSED: when the token cannot be minted, `load_or_create_token_at`
    /// propagates the error (it does not silently emit a weak token). This drives the
    /// `resolve_state_dir_and_token` ephemeral in-memory fallback (server.rs) so the
    /// control plane is unauthorizable rather than guessable. We simulate the mint
    /// failure via an unwritable state dir (the OS CSPRNG itself cannot be un-provisioned
    /// in-process); the propagate-on-failure contract this exercises is the SAME `?` path
    /// a `getrandom` error takes out of `generate_token`.
    #[test]
    fn token_mint_fails_closed_when_it_cannot_be_persisted() {
        // A path whose parent is a FILE, so `ensure_dir_restricted` / write cannot
        // create the token → `generate_token()?` / `write` returns Err, never a token.
        let file = std::env::temp_dir().join(format!(
            "dig-node-failclosed-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::write(&file, b"not a dir").unwrap();
        let bogus = file.join("sub").join(CONTROL_TOKEN_FILE);
        assert!(
            load_or_create_token_at(&bogus).is_err(),
            "must fail closed (propagate), never return a usable token when it cannot mint+persist"
        );
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn load_or_create_token_persists_and_is_stable() {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        let first = load_or_create_token_at(&path).unwrap();
        let second = load_or_create_token_at(&path).unwrap();
        assert_eq!(first, second, "token must be stable across reads");
        assert_eq!(first.len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SECURITY (#501 residual): a pre-existing control-token file that is NOT owned by a
    /// trusted principal (here forced group/other-readable, so not owner-only) MUST be DELETED
    /// and REGENERATED — never returned — so a planted/squatted token can never become the
    /// trusted one (which would hand an attacker full local node control). Unix-gated: it
    /// relies on mode bits (CI runs on Linux). Skipped when running as root, where a
    /// root-owned file is legitimately trusted regardless of mode.
    #[cfg(unix)]
    #[test]
    fn foreign_owned_token_file_is_regenerated_not_trusted() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-untrusted-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let planted = "planted0".repeat(8); // a KNOWN 64-char attacker value (non-empty)
        std::fs::write(&path, &planted).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let running_as_root = std::fs::metadata(&path)
            .map(|m| m.uid() == 0)
            .unwrap_or(false);
        let got = load_or_create_token_at(&path).unwrap();
        if !running_as_root {
            assert_ne!(
                got, planted,
                "an untrusted (group-readable) token must be regenerated, not returned"
            );
            assert_eq!(
                got.len(),
                64,
                "the regenerated token is a fresh 64-hex value"
            );
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode & 0o077,
                0,
                "the regenerated token must be owner-only 0600 (got {mode:o})"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A trusted (owner-only `0600`, current-user-owned) pre-existing token is loaded AS-IS —
    /// never regenerated — so a legit token stays stable across runs (#501 residual).
    #[cfg(unix)]
    #[test]
    fn trusted_owner_only_token_file_is_kept() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-trusted-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let existing = "a".repeat(64);
        std::fs::write(&path, &existing).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let got = load_or_create_token_at(&path).unwrap();
        assert_eq!(
            got, existing,
            "a trusted owner-only token must be loaded as-is, not regenerated"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SECURITY (#501): the control token grants full local control, so the created
    /// file MUST NOT be readable by other local users. On Unix that is a hard `0600`
    /// assertion (no group/other bits) — the CI-gated path (CI runs on Linux). On
    /// Windows the restriction is applied via `icacls` (asserted separately in a
    /// Windows-gated test / by the orchestrator's adversarial ACL check).
    #[cfg(unix)]
    #[test]
    fn created_token_file_is_not_world_or_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-perms-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        load_or_create_token_at(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "token must have NO group/other permission bits (got {mode:o})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The remedy hint names the concrete token path and, when the token is absent from
    /// the caller's perspective, tells them to start the node — never the old generic
    /// "<config_dir>" wording.
    #[test]
    fn control_token_remedy_names_a_concrete_path() {
        let remedy = control_token_remedy();
        assert!(
            remedy.contains("control token") || remedy.contains("control-token"),
            "remedy should mention the control token: {remedy}"
        );
        assert!(
            remedy.contains("dig-node")
                || remedy.contains("state dir")
                || remedy.contains('/')
                || remedy.contains('\\'),
            "remedy should name a path or command: {remedy}"
        );
    }

    /// #772 symptom 2 — the SERVICE-mints ⇄ CLI-reads round-trip: a token minted by the
    /// node-side writer at a path is read back byte-identically by the operator-side reader at
    /// the SAME path. This is the coupling the bug broke (service running yet CLI cannot read
    /// the token); a fresh mint must always be readable at its own path.
    #[test]
    fn service_mint_then_cli_read_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-roundtrip-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        let minted = load_or_create_token_at(&path).unwrap();
        let read_back = read_token_readonly_at(&path).unwrap();
        assert_eq!(
            minted, read_back,
            "the CLI read must return the exact token the service minted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #856 mint-on-startup guarantee: minting on a PRE-EXISTING (already-created, tokenless)
    /// state dir succeeds and is IDEMPOTENT — a second mint returns the SAME token, never leaving
    /// the dir tokenless or churning the token. This models the service startup path re-securing a
    /// half-hardened/recreated dir in place and always converging to a minted token.
    #[test]
    fn mint_on_a_pre_existing_dir_is_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-mint-idempotent-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        // The dir pre-exists but holds NO token (a freshly (re)created state dir).
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CONTROL_TOKEN_FILE);
        assert!(!path.exists(), "precondition: the dir starts tokenless");

        let first = load_or_create_token_at(&path).unwrap();
        assert!(!first.trim().is_empty(), "startup must MINT a token");
        assert!(path.exists(), "the token must be persisted in the dir");

        let second = load_or_create_token_at(&path).unwrap();
        assert_eq!(
            first, second,
            "mint-on-startup must be idempotent — a re-secure of an existing dir keeps the token"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A genuinely-absent token reads as `NotFound` with the "no control token found" remedy that
    /// now ALSO names the stale-service reinstall recovery (#772).
    #[test]
    fn read_readonly_reports_absent_token_as_not_found() {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-absent-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        let err = read_token_readonly_at(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let msg = err.to_string();
        assert!(msg.contains("no control token found"), "{msg}");
        assert!(
            msg.contains("reinstall") && msg.contains("STALE"),
            "the absent-token remedy must name the stale-service reinstall recovery: {msg}"
        );
    }

    /// #772 symptom 2 (the ACL split): a token present but UNREADABLE by the invoking user must
    /// map to `PermissionDenied` ("elevate / reinstall"), NEVER the misleading `NotFound` the old
    /// `path.exists()` classification produced. Unix mode-bit gated; skipped as root (root
    /// bypasses the mode bits).
    #[cfg(unix)]
    #[test]
    fn unreadable_token_maps_to_permission_denied_not_not_found() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-denied-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "a".repeat(64)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let running_as_root = std::fs::read_to_string(&path).is_ok();
        if !running_as_root {
            let err = read_token_readonly_at(&path).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "an unreadable token must be PermissionDenied, not NotFound"
            );
            assert!(
                err.to_string().contains("NOT readable"),
                "the remedy must explain the token is present but unreadable: {err}"
            );
        }
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_store_ref_validates_hex_and_splits_capsule() {
        let store = "a".repeat(64);
        let root = "b".repeat(64);
        assert_eq!(parse_store_ref(&store).unwrap(), (store.clone(), None));
        assert_eq!(
            parse_store_ref(&format!("{store}:{root}")).unwrap(),
            (store.clone(), Some(root.clone()))
        );
        assert!(parse_store_ref("nothex").is_err());
        assert!(parse_store_ref(&format!("{store}:nothex")).is_err());
    }

    #[test]
    fn pin_registry_roundtrips_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-pins-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let config_path = dir.join("config.json");
        let _ = std::fs::remove_dir_all(&dir);
        let store = "c".repeat(64);
        let root = "d".repeat(64);

        assert!(read_pins_from(&config_path).is_empty());
        add_pin(&config_path, &store, Some(&root)).unwrap();
        // Idempotent: pinning the same store again does not duplicate it.
        add_pin(&config_path, &store, Some(&root)).unwrap();
        let pins = read_pins_from(&config_path);
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0]["store_id"], json!(store));
        assert_eq!(pins[0]["root"], json!(root));

        assert!(remove_pin(&config_path, &store).unwrap());
        assert!(read_pins_from(&config_path).is_empty());
        // Removing an absent pin is a no-op false.
        assert!(!remove_pin(&config_path, &store).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_config_preserves_dig_node_keys() {
        // This service's pin/upstream writes must NOT clobber dig-node's own keys
        // in the shared config.json (cache_cap_bytes, wc_project_id).
        let dir = std::env::temp_dir().join(format!(
            "dig-node-config-merge-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let config_path = dir.join("config.json");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&json!({ "cache_cap_bytes": 12345, "wc_project_id": "abc" }))
                .unwrap(),
        )
        .unwrap();

        let store = "e".repeat(64);
        add_pin(&config_path, &store, None).unwrap();
        set_upstream_override(&config_path, "https://example.test").unwrap();

        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(v["cache_cap_bytes"], json!(12345), "dig-node key preserved");
        assert_eq!(v["wc_project_id"], json!("abc"), "dig-node key preserved");
        assert_eq!(v["pinned_stores"][0]["store_id"], json!(store));
        assert_eq!(v["upstream_override"], json!("https://example.test"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upstream_override_roundtrips_and_clears() {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-upstream-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let config_path = dir.join("config.json");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read_upstream_override_from(&config_path), None);
        set_upstream_override(&config_path, "https://up.test").unwrap();
        assert_eq!(
            read_upstream_override_from(&config_path),
            Some("https://up.test".to_string())
        );
        // Blank clears it.
        set_upstream_override(&config_path, "  ").unwrap();
        assert_eq!(read_upstream_override_from(&config_path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (#1851 leg-2) `control.wallet.balance` MUST emit `balance`/`pending` as JSON **numbers**,
    /// matching `dig-node-control-interface` 0.3.0's `WalletBalanceResult { balance: u64, .. }`
    /// and dig-app-core's `BalanceResponse { balance: u64 }`. This is the property under test —
    /// distinguished from the nearest wrong implementation (`r.balance.to_string()`, which
    /// produces a `Value::String` that LOOKS identical when printed but fails `u64` deserialize)
    /// by asserting deserialization into a `u64`-typed mirror struct, not just string-equality
    /// against the printed JSON.
    #[test]
    fn balance_wire_emits_numeric_amounts_matching_app_contract() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::WalletBalanceResult;

        #[derive(serde::Deserialize)]
        struct AppBalance {
            balance: u64,
        }

        let r = WalletBalanceResult {
            balance: 12_345,
            pending: 6,
            source: Source::Db,
            synced: true,
            peak_height: Some(42),
        };
        let emitted = balance_wire(&r);

        // Golden shape: numeric, not string.
        assert_eq!(
            emitted,
            json!({
                "balance": 12345u64, "pending": 6u64,
                "source": "db", "synced": true, "peak_height": 42
            }),
        );
        assert!(
            emitted["balance"].is_number(),
            "balance must be a JSON number, not a string"
        );
        assert!(
            emitted["pending"].is_number(),
            "pending must be a JSON number, not a string"
        );

        // Load-bearing: dig-app's numeric-typed struct deserializes cleanly from the emitted
        // value. A `.to_string()`-based emission (`Value::String("12345")`) fails THIS
        // assertion with a "invalid type: string, expected u64" error.
        let app: AppBalance =
            serde_json::from_value(emitted).expect("numeric balance must deserialize into u64");
        assert_eq!(app.balance, 12_345);
    }

    /// Saturating-cast guard: a `u128` balance beyond `u64::MAX` clamps rather than panicking,
    /// so the RPC call stays alive (clamped-but-answered) instead of crashing on an implausible
    /// overflow.
    #[test]
    fn balance_wire_saturates_u128_overflow_to_u64_max() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::WalletBalanceResult;

        let r = WalletBalanceResult {
            balance: u128::from(u64::MAX) + 1,
            pending: 0,
            source: Source::Fallback,
            synced: false,
            peak_height: None,
        };
        let emitted = balance_wire(&r);
        assert_eq!(emitted["balance"], json!(u64::MAX));
    }

    /// (#2233) The tier reaches the WIRE as the lowercase token a consumer keys on, for BOTH
    /// tiers — so a mapper that dropped the field, or emitted the Rust variant name (`"Db"`),
    /// fails here rather than at a consumer.
    ///
    /// The `source` field is ADDITIVE (§5.1): the same test asserts a consumer struct that
    /// does not know about it still deserializes, so ignoring it cannot break a caller.
    #[test]
    fn balance_wire_discloses_the_answering_tier_additively() {
        use dig_wallet::sage::routing::Source;
        use dig_wallet::sage::rpc::WalletBalanceResult;

        #[derive(serde::Deserialize)]
        struct OldConsumer {
            balance: u64,
            synced: bool,
        }

        for (source, wire) in [(Source::Db, "db"), (Source::Fallback, "fallback")] {
            let emitted = balance_wire(&WalletBalanceResult {
                balance: 1,
                pending: 0,
                source,
                synced: source == Source::Db,
                peak_height: None,
            });
            assert_eq!(emitted["source"], json!(wire));

            let old: OldConsumer = serde_json::from_value(emitted)
                .expect("a consumer unaware of `source` must still parse");
            assert_eq!(old.balance, 1);
            assert_eq!(old.synced, source == Source::Db);
        }
    }
}
