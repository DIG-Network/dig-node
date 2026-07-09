# dig-node — normative specification

`dig-node` is the DIG Network's **local content node**: the RPC endpoint a client connects to in order
to read `dig://` / `chia://` content, and — in its standalone form — a full participant in the L7
DIG-Node peer-to-peer network. It stores content as `.dig` capsule modules, watches Chia for the
generations of the stores it holds, actively syncs the generations it is missing from other nodes,
serves verified content to clients, and locates + relays content across the peer network.

This document is the authoritative, normative contract an independent reimplementation MUST be
buildable against. Keywords **MUST**, **MUST NOT**, **SHALL**, **SHOULD**, **MAY** are used as in
RFC 2119. Where a clause states target behaviour the current reference code does not yet fully meet,
it is marked **(target)**; unmarked clauses describe the behaviour the reference crate implements
today. Behaviour that contradicts this document is a bug in the code OR in this document — they are
kept in agreement in the same unit of work as any change (`CLAUDE.md` §4.2).

**Cross-references (this SPEC MUST NOT contradict them):**
- Ecosystem cross-repo contract map: superproject `SYSTEM.md` (dual-transport RPC tiers, the shared
  `CandidateAddr`/`dig.getPeers` shapes, anchored-root pin, RelayMessage/RLY-008, the onion-routing
  DESIGNED row).
- L7 peer-network protocol: `docs.dig.net/docs/protocol/peer-network.md` (mTLS peer identity, the two
  RPC tiers, the NAT ladder, the DHT wire, PEX, redirect-on-miss `-32008`).
- Onion privacy layer: superproject `DESIGN_ONION_ROUTING.md` (design + threat model) and
  `modules/crates/dig-onion/SPEC.md` (the onion crate's normative contract). §8 here specifies the
  dig-node's PARTICIPATION contract; it does NOT re-derive the circuit crypto — that is dig-onion's.
- Composed crates: `dig-nat`, `dig-gossip`, `dig-dht`, `dig-pex`, `dig-download`, `dig-peer-selector`,
  `dig-onion` (superproject `CLAUDE.md` Appendix B).
- The DIG store format + read crypto (`digstore-core`/`-host`/`-crypto`/`-chain`/`-remote`/`-stage`),
  which dig-node consumes and MUST NOT reimplement.

---

## 1. Roles, deployment modes, and the process model

`dig-node` is the SUPPLY side of the network (`SYSTEM.md` "Roles — serving vs consuming"): it hosts,
syncs, and serves content, and exposes the dig RPC so consumers (the DIG Browser, the extension, the
SDK) can read it. It runs in exactly two forms, and the form determines what surfaces come up:

### 1.1 Standalone binary (the node)

The `dig-node` binary (`src/main.rs` → `dig_node::run`) is a self-contained OS-service node with NO
Node/runtime dependency. On startup it:

- Serves the **client-facing JSON-RPC read surface** over HTTP on loopback `127.0.0.1:{DIG_NODE_PORT}`
  (default **9778**), plus `GET /health`.
- Brings up the **L7 peer network** (§7): the mTLS peer-RPC listener, the dig-gossip connected pool +
  relay introducer, the dig-dht content-location DHT, dig-pex peer exchange, and the multi-source
  content-fetch engine — unless disabled by `DIG_PEER_NETWORK=off`.
- Runs the **chain-watch + gap-fill loop** (§4.3, §5.1): polls each subscribed store's (§6) singleton
  on an interval and actively pulls down + verifies any confirmed generation it is missing.

The loopback HTTP read surface is the local face of the network-wide **public read tier**; when a node
is exposed to the wider network as `rpc.dig.net`, that same read surface is served TLS-fronted on a
public interface (§2.1). A node run purely for a local consumer keeps the read surface on loopback.

### 1.2 In-process (the browser's embedded consumer node)

The DIG Browser links `dig-node` in-process (via the `dig-runtime` cdylib FFI) and drives it through
`handle_rpc(json) -> json` with NO socket. In this form the node is a **pure consumer**:

- It MUST NOT open any peer-network listener, DHT, PEX, relay reservation, or multi-source fetch
  engine (`p2p_content` is never set).
- A content miss therefore has NO redirect/fetch-through behaviour — the miss handler is a no-op and
  the request falls through to the upstream proxy.
- The byte-exact `dig.getContent` / §21 read contract MUST be identical to the standalone read
  surface, so the browser and the standalone node are interchangeable read endpoints.

Both forms share ONE on-disk cache and config by construction (§3.4), so a browser and a co-installed
standalone node coordinate their `.dig` cache and never store a capsule twice.

---

## 2. RPC interface (client-facing)

The node is the RPC endpoint clients connect to. It presents its methods on **two tiers with two
authentication models** (`SYSTEM.md` "Dual-transport RPC tiers"; peer-network doc §0/§7a), and clients
resolve *which node* to talk to by a fixed ladder (§2.2).

### 2.1 The two transport tiers

| | **PUBLIC-READ tier** | **PEER/CONTROL tier** |
|---|---|---|
| Purpose | browser/agent + local-consumer **content read** | node↔node + node-class clients: discovery, DHT, PEX, availability-for-sync, write/push, config/control |
| Auth | **none** — anonymous, no client cert, CORS-`*` for reads | **mutual TLS**; `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`; write routes additionally per-request BLS-signed (§21.9) |
| Transport | plain HTTPS JSON-RPC (network face = `rpc.dig.net`); loopback HTTP for the local consumer | the dig-nat mTLS yamux mux on `[::]:{DIG_PEER_PORT}` (default 9444); the §21 authenticated HTTPS write routes |
| Browser-reachable | **Yes** (the read path) | **No** — an anonymous caller cannot open it |
| Integrity trust | **client-side self-verification** (merkle inclusion proof + chain-anchored root pin — server untrusted) | mTLS peer identity |

**Boundary invariant (NORMATIVE, `SYSTEM.md` + peer-network doc §0):**

1. **No peer / write / config / control method is reachable without mTLS.** On the anonymous read
   listener these methods do not exist — an anonymous caller that names one receives `-32601`
   (method not found). A node MUST NOT honor a write/peer/control method on a connection that did not
   complete the mTLS handshake.
2. **Content read requires no mTLS.** The read methods (§2.3) are served anonymously so a browser
   works; they are read-only, self-verified client-side, and answer a miss with a decoy/redirect,
   never a presence oracle.

**Implementation status.** The reference binary today serves the read-subset JSON-RPC over loopback
HTTP (`127.0.0.1:{DIG_NODE_PORT}`) and the peer/control methods over the mTLS mux; the loopback read
listener is not a public interface. A conforming public deployment (`rpc.dig.net`) MUST serve the read
subset with `Access-Control-Allow-Origin: *`, no credentials, `OPTIONS`→204, and MUST return `-32601`
for any peer/write/control method **(target for the public-facing serve split)**.

### 2.2 Client → node resolution order (`CLAUDE.md` §5.3)

A client that needs a node MUST resolve the endpoint in this fixed order, using the first that
responds to a cheap health probe with a short timeout, caching the choice for the session:

1. an explicitly-configured node (a `--node` flag / `$DIG_NODE_URL` / stored config) — **always wins**,
   overriding the ladder entirely;
2. `dig.local` — the installed local node (the installer's hosts registration);
3. `localhost` (the node's default local read port) when `dig.local` is not registered;
4. `rpc.dig.net` — the public gateway, FINAL fallback only.

A node-class client (one holding a DIG identity key — the digstore CLI, the SDK, any filesystem
client) connects over **mTLS**, presenting a client cert derived from its DIG identity key, at every
tier including `rpc.dig.net` (dual-mode: an mTLS endpoint for node-class clients plus the plain-HTTPS
public read tier browsers require). A browser/agent uses the plain-HTTPS public read tier. A client
MUST NOT hard-code `rpc.dig.net` as the primary endpoint. dig-node itself is the *server* end of this
ladder; its own upstream fallback for a miss (`DIG_NODE_UPSTREAM`, default `https://rpc.dig.net/`) is
the node's own client-side use of tier 4.

### 2.3 Method surface

All methods are JSON-RPC 2.0 (`POST`, by-name params) and return the standard envelope. Field types:
`64hex` = 32 raw bytes rendered lower-case hex; `u64` = unsigned integer; base64 = standard base64.

#### 2.3.1 Content read (PUBLIC-READ tier)

**`dig.getContent`** — read a resource window.
- params: `{ store_id: 64hex, retrieval_key: 64hex, root: 64hex|"" (empty ⇒ rootless, resolve to the
  chain tip), offset: u64 (default 0), mode?: "speed"|"privacy" (§2.5, target) }`.
- result (one window; see the chunk object §2.4): `{ ciphertext: base64, root: 64hex, complete: bool,
  next_offset?: u64 (present iff not complete), inclusion_proof?: base64 (first window only),
  chunk_lens?: [u32] (first window only) }`.
- The served bytes MUST be pinned to the chain-anchored root (§4); a mismatch/unreachable chain fails
  closed with `-32005`. A miss is answered by a decoy or, on a peer node, the redirect (§5.4) — never
  a bare not-found while a holder exists.

**`dig.getAnchoredRoot`** — resolve a store's current chain-anchored root.
- params: `{ store_id: 64hex }`. result: `{ root: 64hex }`. Errors: `-32602`, `-32000` (chain read
  failure). This is a control/read helper; a browser resolves the anchored root from its own chain
  source, not from a serving node it does not trust.

**`dig.getCapsule`** (alias `dig.getModule`), **`dig.getManifest`**, **`dig.getMetadata`**,
**`dig.getProof`** / **`dig.getProofStatus`**, **`dig.listCapsules`**, **`dig.health`**,
**`dig.methods`** — the remaining read/discovery subset of the dig RPC (`docs.dig.net` dig-rpc spec);
each is read-only, anonymous, and self-verified client-side. The §21 GET routes
(`content`/`proof`/`roots`/`descriptor`) are the REST face of the same tier.

**`dig.getCollection`** / **`dig.listCollectionItems`** — resolve an on-chain collection (DID + item
launchers).
- `dig.getCollection` params: `{ launcher_ids: [64hex], did?: 64hex }`; result:
  `{ did, declared_did, item_count, resolved_count, royalty_basis_points }`. Errors `-32602`, `-32000`.
- `dig.listCollectionItems` params: `{ launcher_ids: [64hex], offset?: u64, limit?: u64 (≤200) }`;
  result: `{ items: [...], offset, limit, total, next_offset }`. Error `-32602`.
- Each launcher id costs one chain read, and both methods are peer-reachable (§7.4a), so
  `launcher_ids` is CAPPED at **10,000** entries — an over-cap array is rejected with `-32602`
  BEFORE any chain read (bounds the peer-triggered outbound fanout). `dig.getCollection` resolves
  the whole (capped) array per call; `dig.listCollectionItems` additionally paginates within it at
  ≤200 items per page.

#### 2.3.2 Node cache + control (CONTROL, loopback / in-process ONLY)

These are loopback-authorized control methods (in-process FFI or the local read port). They are
**management/mutation** methods and MUST NOT be reachable over the mTLS peer surface (§7.4): the
peer verifier accepts any well-formed self-signed leaf, so an "authenticated" peer is merely "some
`peer_id`", never an authorized administrator. The peer responder enforces a method **allowlist**
(§7.4a) and returns `-32601` (method not found) for any method in this section — a remote peer can
never call `cache.clear` / `cache.setCapBytes` / `cache.removeCached` / `cache.fetchAndCache` /
`cache.listCached` / `cache.getConfig` / `control.peerStatus` / `control.subscribe` /
`control.unsubscribe` / `control.listSubscriptions` / `dig.stage`. They stay reachable only from the
loopback admin / in-process FFI dispatch (`handle_rpc`).

- **`cache.getConfig`** → `{ cap_bytes: u64, used_bytes: u64, cache_dir: string, shared: bool }`.
- **`cache.setCapBytes`** `{ cap_bytes: u64 }` → `{ cap_bytes: u64 (effective) }`; the value is floored
  at **64 MiB**. Error `-32032` `CONTROL_ERROR` on write failure. This is the single source of truth
  for the cache cap — the browser's `chrome://settings` handler and the wallet config endpoint both go
  through it.
- **`cache.clear`** → `{}`.
- **`cache.listCached`** → the durable module inventory: `{ cached: [ { capsule: "storeId:rootHash",
  store_id: 64hex, root: 64hex, size_bytes: u64, last_used_unix_ms: u64 } ] }` (§3, §6).
- **`cache.removeCached`** `{ store_id: 64hex, root: 64hex }` → `{ removed: bool }`. Error `-32602`.
- **`cache.fetchAndCache`** `{ store_id: 64hex, root: 64hex }` → `{ status:
  "cached"|"already_cached"|"failed", size_bytes?: u64, served_root?: 64hex, message?: string }`.
- **`control.peerStatus`** → the peer-network status snapshot (§7.2); always safe to call, reports
  "not running" on the FFI path.
- **`control.subscribe`** `{ store_id: 64hex }` → `{ subscribed: true, added: bool, store_id }`,
  **`control.unsubscribe`** `{ store_id: 64hex }` → `{ subscribed: false, removed: bool, store_id }`,
  **`control.listSubscriptions`** → `{ subscriptions: [64hex], count: u64 }` — manage the node's
  persisted subscribed-store set (§6.1), which drives the chain-watch (§4.3) + gap-fill (§5.1) loop. A
  malformed `store_id` → `-32032` `CONTROL_ERROR` (with `data.code`/`data.origin`, §2.6).
- **`dig.stage`** — compile a folder into a capsule module in-process (`{ dir, store_id?, salt?,
  metadata? }` → `{ capsule, store_id, root, module_path, size, ... }`). Errors: `-32602`, `-32011`
  (dir not readable), `-32012` (no files), `-32013` (over the store cap), `-32014` (compile/IO).
  The directory walk is BOUNDED — it aborts (`-32011`) the moment the running total exceeds a
  maximum-bytes-read budget, the file count exceeds a maximum, or recursion exceeds a depth cap —
  so an over-large or pathological `dir` cannot be read wholesale into memory before the store-cap
  compile check runs. This is a loopback/in-process-only method (§2.3.2, §7.4a).

#### 2.3.3 Peer / sync (PEER/CONTROL tier)

`dig.getNetworkInfo`, `dig.getPeers`, `dig.announce`, `dig.getAvailability`, `dig.listInventory`,
`dig.fetchRange`, and the DHT/PEX methods are specified in §7.4. They are reachable ONLY over mTLS.

Any unknown method returns `-32601`.

### 2.4 The content window / chunk wire object

A `dig.getContent`/`dig.fetchRange` response pages the resource ciphertext in windows of at most
`WINDOW = 3 MiB`. The wire object (matching `rpc.dig.net` / the digstore client / `SYSTEM.md`
"JSON-RPC 2.0 read methods") is:

- `ciphertext` (base64) — this window of the resource's chunk-ciphertext (the plain concatenation of
  the resource's AES-256-GCM-SIV chunk ciphertexts; NO length framing in the bytes).
- `root` (64hex) — the chain-anchored generation root the window verifies under.
- `complete` (bool) — whether this window ends the resource; `next_offset` (u64) is present iff not.
- `inclusion_proof` (base64) — the merkle inclusion proof of the whole resource under `root`, sent on
  the **first window only** (offset 0). The client keeps the first non-empty proof.
- `chunk_lens` ([u32]) — the per-chunk ciphertext lengths of the whole resource, in order, sent on the
  **first window only**. The client splits `ciphertext` by these and AES-256-GCM-SIV-opens each chunk.

`chunk_lens` is serving metadata, NOT covered by the merkle leaf (`leaf = SHA-256(ciphertext)`). The
wire is backwards-compatible: a module from a pre-`chunk_lens` producer emits none, and a decoder reads
`chunk_lens` only if trailing bytes remain (`digstore_core::wire::ContentResponse`) — consistent with
the DIG-format backwards-compatibility HARD RULE (`CLAUDE.md` §5.1).

### 2.5 Content-retrieval modes — speed vs privacy (target)

Content retrieval takes a mode as a first-class, optional request field, defaulting to `speed`:
`mode ∈ { "speed", "privacy" }`.

- **SPEED** (default) — the multi-source fast path: locate holders via the DHT, rank via
  `dig-peer-selector`, fan byte-ranges across multiple providers via `dig-download`, verify each range
  (§5.3). Providers see the requester's node.
- **PRIVACY** — an onion-routed retrieval through the dig-onion telescoping circuit (§8), hiding the
  requester from providers and from any single relay, at the cost of latency + single-path throughput.

An implementation MUST treat an absent `mode` as `speed` (legacy clients unchanged), MUST NOT route a
`speed` request through a circuit, and MUST satisfy the §8 privacy invariants for a `privacy` request.

**Implementation status: NOT YET PRESENT.** The reference code has no `mode` field and no onion path;
the mode toggle + privacy routing is the dig-node integration phase of task #194 (`DESIGN_ONION_
ROUTING.md §11` Phase 4). §2.5 + §8 are the normative target the integration is built to.

### 2.6 Error-code catalog

| Code | Name | Meaning |
|---|---|---|
| `-32700` | parse error | request body was not valid JSON-RPC |
| `-32601` | method not found | unknown method, OR a peer/write/control method named on the anonymous read tier |
| `-32602` | invalid params | missing/malformed params (bad hex, wrong type, out-of-range) |
| `-32000` | server error | upstream failure, chain read failure, file I/O, config write |
| `-32004` | resource unavailable | this node does not hold the content AND located no holder (genuine not-found) |
| `-32005` | `ROOT_NOT_ANCHORED` | served/requested root ≠ chain-anchored root, chain unreachable, or no confirmed generation (§4) — the read-path pin failing closed |
| `-32006` | `PEER_UNREACHABLE` | no traversal strategy reached the named peer |
| `-32007` | `RANGE_NOT_SATISFIABLE` | `offset ≥ total_length` or the range is otherwise unsatisfiable |
| `-32008` | `CONTENT_REDIRECT` | this node does not hold the content but located holders — a redirect, not a 404 (§5.4) |
| `-32011`..`-32014` | stage errors | dir not readable / no files / over cap / compile-IO (`dig.stage`) |
| `-32020` | `ONION_CIRCUIT_UNAVAILABLE` | (target) a `mode:"privacy"` request could not be served privately — MUST NOT downgrade (§8) |
| `-32021` | `PRIVACY_REQUIRES_LOCAL_NODE` | (target) `mode:"privacy"` on a node with no trusted local originator |
| `-32022` | `ONION_HOPS_OUT_OF_RANGE` | (target) requested hop count outside `[2,5]` |
| `-32030` | `UNAUTHORIZED` | a control-plane call is not authorized (loopback / token gate) |
| `-32031` | `NOT_SUPPORTED` | a control-plane method is recognized but not supported on this node |
| `-32032` | `CONTROL_ERROR` | a control-plane runtime error (subscription persistence, config write, sync trigger) |

Codes MUST match the `docs.dig.net` error catalog, the `dig-rpc-types` taxonomy, and the dig-onion SPEC
byte-for-byte. The onion codes `-32020`/`-32021`/`-32022` are RESERVED for private retrieval; the
control-plane codes are renumbered CLEAR of them to `-32030`/`-32031`/`-32032` (matching
`dig-rpc-types` §10). Control-plane errors carry the canonical `{code, message, data:{code, origin}}`
envelope — `data.code` the `UPPER_SNAKE_CASE` machine key, `data.origin` = `"control"`.

---

## 3. Content storage + optimization (.dig)

The node stores content as **capsule modules** — the digstore `.dig` compiled-WASM format. It does NOT
reimplement that format; it consumes `digstore-host`/`-core`/`-crypto`/`-stage` and holds the storage
contract + invariants below.

### 3.1 What a stored capsule is

A **capsule** is one immutable generation of a store, `(store_id, root)` (`SYSTEM.md` "Core concept").
The node stores it as the compiled module bytes for that `(store_id, root)`. A capsule compiles to one
fixed-size module (padded to `digstore-compiler::FIXED_BLOB_LEN` ≥ `MAX_STORE_BYTES = 128_000_000`), so
capsule length leaks nothing about content size — a property the node MUST preserve (it never serves a
size-revealing artifact for a capsule). Content at rest is encrypted (AES-256-GCM-SIV, HKDF-SHA256
key); the node holds ciphertext + merkle proofs and serves provider-blind, exactly as a remote host
does. A LOCAL node MAY additionally verify+decrypt for its own consumer (it is the user's machine),
but the stored artifact and the served wire stay ciphertext + proof.

### 3.2 On-disk layout

- Module store: `<cache_dir>/<store_id_hex>/<root_hex>.module` — the compiled module bytes for that
  capsule. Keyed by `(store_id, root)`; a client sends a concrete root (a rootless URN is resolved to
  the singleton tip first), so a module is uniquely addressed.
- Proxied-response cache: `<cache_dir>/responses/<store>_<root>_<retrieval_key>_<offset>.json` — a
  previously-proxied JSON-RPC read window. The filename MUST neutralize non-hex input (no path
  traversal).
- Peer-network state: `<cache_dir>/peer-net/` (the node's TLS cert/key + peer address book, §7).
- Download staging: `<cache_dir>/downloads/` (+ `.download.tmp` GC), for the multi-source engine (§5).
- Lockfile + config: a cross-process advisory flock serializes cache/config RMW; `config.json` holds
  `cache_cap_bytes` and `wc_project_id`.

### 3.3 Serving a capsule + ranges

- A read is served from a locally cached module via `digstore_host::serve_blind(module, retrieval_key,
  cfg)`, which instantiates the compiled module and returns a `ContentResponse` = ciphertext + merkle
  proof + `chunk_lens`. The serve host key is local/ephemeral: the client verifies against the
  chain-anchored root, not against a host signature.
- The whole-module read + `serve_blind` decrypt runs on a BLOCKING thread (`spawn_blocking`), never on
  an async worker, and the decoded `ContentResponse` is MEMOIZED in a bounded in-memory LRU keyed by
  `(store, root, retrieval_key)` (default 256 MiB, least-recently-used eviction). Successive windows of
  the same streamed resource slice from the cached decode instead of re-reading + re-decrypting the
  whole module per window — O(n) instead of O(n²) over a streamed resource. The decoded cache is
  invalidated for a capsule when its module is removed/replaced (`cache.removeCached` / a re-synced
  module) and fully cleared by `cache.clear`, so a removed capsule is never served from RAM.
- `dig.fetchRange` serves a byte range `[offset, offset+length)` of a resource or whole capsule,
  `length` clamped to `WINDOW` (3 MiB) and widened to whole-chunk boundaries so each returned chunk is
  a complete verifiable unit; the first frame carries `total_length` + `chunk_lens` + `chunk_index` +
  `inclusion_proof` + `root` (§7.4). A capsule (`capsule: true`) self-verifies on install, so its
  `inclusion_proof` is null.

### 3.4 Cache: shared location, cap, and LRU

- **Shared canonical dir.** The in-process browser node and the standalone node MUST resolve the SAME
  cache dir so they share one `.dig` cache (`SYSTEM.md` #96). Resolution precedence: (1)
  `DIG_NODE_CACHE` if set non-empty; (2) the per-OS base dir — Windows `%LOCALAPPDATA%`
  (`data_local_dir()`), Unix/macOS `$HOME` — suffixed `DigNode/cache`; (3) `./DigNode/cache`. If the
  canonical dir is unwritable, the node falls back to a process-private location (NOT shared).
  `cache.getConfig.shared` reports whether the shared location is in use.
- **Size cap + eviction.** The on-disk cache is bounded by `cap_bytes` (from `config.json`
  `cache_cap_bytes`, else `DIG_NODE_CACHE_CAP`, else `DEFAULT_CACHE_CAP = 1 GiB`), floored at 64 MiB on
  set. When the cache exceeds the cap, the node evicts by **LRU** (oldest mtime first) until the total
  fits; a read touches the file mtime for recency. Capsule modules are the durable inventory (§6) and
  are removed explicitly via `cache.removeCached` / `cache.clear`, not silently evicted mid-serve.
- Concurrent cache/config mutation is serialized by an in-process mutex AND the cross-process flock.

### 3.5 Integrity invariant

Every window/range the node serves — from a local module, a synced module, a cached response, or a
fetch-through pull — MUST carry the same verification metadata (`total_length`, `chunk_lens`,
`inclusion_proof`, `root`) so it is indistinguishable in shape and the client verifies it against the
chain-anchored root. The node MUST NOT serve content under a root it has not confirmed on-chain (§4).

---

## 4. Chain watching

The node treats the **Chia chain as the authority** for which generation a read serves (`SYSTEM.md`
"Anchored-root pin"). It watches the CHIP-0035 DataLayer singleton of each store it deals with to know
the current root.

### 4.1 The anchored-root resolver

- The trusted-root source is an injectable `AnchoredRootResolver`:
  `async fn anchored_root(store_id) -> Result<Option<Bytes32>, _>` — `Ok(Some(root))` = the confirmed
  unspent-singleton tip's `metadata.root_hash`; `Ok(None)` = the store has no confirmed generation;
  `Err` = the chain is unreachable.
- Production uses `CoinsetResolver`, which walks the singleton via
  `digstore_chain::singleton::sync_datastore` over a coinset endpoint (`Coinset::mainnet()` /
  `api.coinset.org`, overridable by `DIG_NODE_COINSET`). Tests inject a deterministic resolver so the
  fail-closed gate is unit-testable without a chain.

### 4.2 The read-path pin (fail-closed, `-32005`)

Before serving ANY content the node resolves the store's anchored root and gates on it:

- pin disabled (`DIG_NODE_PIN=off`/`0`/`false`) → serve unpinned (offline opt-out only);
- chain error → reject `-32005`;
- `Ok(None)` (no confirmed generation) → reject `-32005` ("no confirmed on-chain generation");
- an explicit requested root ≠ the anchored tip → reject `-32005` ("root mismatch");
- otherwise → serve at the anchored tip (a rootless request resolves to it).

The pin is enforced by DEFAULT and re-validated on every serve path (local module, §21 sync, cached
window, upstream proxy). A compromised upstream/host can never choose which generation is served, and a
module with no on-chain anchor is rejected, never silently downgraded to a no-op. This is uniform with
the CLI `clone`/`pull` pin ("chain is the authority", fail closed).

### 4.3 State tracked + confirmation semantics

- Per store the node needs only its `store_id`; the anchored root is resolved on demand and is the sole
  authority for the current generation. The resolver holds no persistent chain state; a resolution is
  a live singleton walk. "Confirmed" = the singleton's unspent tip as coinset reports it.
- **Poll/subscribe.** In ADDITION to the on-demand per-read resolution, the standalone node runs a
  background **chain-watch loop** (`crate::chainwatch`) that polls each SUBSCRIBED store's (§6)
  singleton on an interval (`DIG_NODE_WATCH_INTERVAL`, default 30 s, floored at 1 s), so a new
  generation is detected without a client read driving it. Each tick resolves the store's anchored root
  via the SAME injectable `AnchoredRootResolver` the read-path pin uses; the confirmation semantics are
  identical (unspent-tip root is the authority, fail-closed on unreachable / no confirmed generation —
  the loop NEVER gap-fills against a root the chain could not confirm). The watcher runs only in the
  standalone peer-network form (it drives §5.1 gap-fill, which needs the peer network); the in-process
  FFI consumer runs no watcher.

---

## 5. Active sync — pulling the generations it is missing

On learning a store advanced (a new root/generation it lacks), a node reconciles its local store to
the new chain root by seeking other nodes that hold the missing content and pulling it, verifying every
byte against the chain-anchored root. Two mechanisms exist; both end in the same verification.

### 5.1 Gap-fill algorithm

1. **Detect.** Resolve the store's anchored root (§4). If the confirmed tip is a root the node does not
   hold locally (`<cache>/<store>/<root>.module` absent), the node is missing that generation.
2. **Locate.** Query the DHT `find_providers` for the content key of the missing capsule
   (`ContentId::capsule(store_id, root)`; §7.5) to find the `peer_id`s that hold it, backed by the
   introducer + `dig.getPeers` peer discovery.
3. **Confirm.** `dig.getAvailability` (batch) against the located candidates — keep only peers that
   actually hold the resource/capsule, and read `total_length` + `chunk_count` to plan ranges.
4. **Pull.** Fetch the missing generation over the peer network (§5.2/§5.3), verify (§5.3), and cache
   it under `(store_id, root)`. The node MUST fill generations toward the confirmed tip; it MUST NOT
   serve a generation it has not both fetched AND verified against the chain-anchored root.

**Ordering + status.** Two triggers drive gap-fill, both ending in the mandatory §5.3 verification:
(a) ON-DEMAND — a concrete `(store, root)` read miss triggers the authenticated whole-module §21 sync
(§5.2) or the multi-source range fetch (§5.3); and (b) PROACTIVE — the standalone node's chain-watch
loop (§4.3), each tick, resolves every SUBSCRIBED store's anchored tip and, when that confirmed
generation is not held locally (`<cache>/modules/<store>/<root>.module` absent), pulls it down via
`Node::gap_fill_generation` (the authenticated §21 whole-store sync, landed under `(store, root)`),
then refreshes the DHT provider records (§6.2) so peers find the node as a new holder. The pull is
idempotent (an already-held generation is a cheap success) and interruption-retrying — a failed pull is
simply retried on the next tick, and an interrupted transfer resumes via the underlying downloader's
per-range resume (§5.3). A node MUST NOT serve a gap-filled generation it has not verified against the
chain-anchored root — the read-path pin (§4.2) re-validates on every serve, so a wrong-generation or
tampered pull can never be served as current.

### 5.2 Authenticated whole-store sync (§21)

On a local miss for a concrete `(store, root)`, the node MAY fetch the WHOLE `.dig` module from the
§21 `GET /stores/{id}/module` endpoint of its upstream (`DIG_NODE_UPSTREAM`, default `rpc.dig.net`),
cache it, then serve every subsequent resource in that store locally.

- That endpoint is dighub-auth-gated (401 for anonymous clients), so the node carries a native Chia
  §21.9 identity signer. It stamps `X-Dig-Identity` / `X-Dig-Timestamp` / `X-Dig-Nonce` / `X-Dig-Auth`
  (canonical message per `SYSTEM.md` "Per-request BLS identity auth") using the SAME persistent
  identity key the digstore CLI uses (`digstore_remote::identity`), minting a fresh `RequestIdentity`
  per request from the persisted 32-byte seed.
- The signer is best-effort: with no identity key the node skips authenticated sync and falls back to
  the per-resource proxy (still serving whatever modules are present). A sync is accepted only after
  the served module's root is confirmed against the chain-anchored root (§4).

### 5.3 Multi-source download + the verification invariant

When the node pulls content over the peer network (§7.6), it uses the `dig-download` multi-source
orchestrator: locate holders (DHT) → rank sources (`dig-peer-selector`) → fan byte-ranges across
multiple providers simultaneously over `dig.fetchRange` → verify → reassemble, with per-range resume
(an interrupted transfer re-fetches only the missing ranges from any holder).

**Verification invariant (NORMATIVE — a node NEVER trusts pulled bytes).** Every range pulled from
another node MUST be verified before it is used or served:

- the range maps to whole chunk(s) (widened to `chunk_lens` boundaries);
- its `inclusion_proof` MUST verify (fold from `leaf = SHA-256(resource ciphertext)` to the proof's own
  root) AND that root MUST equal the **chain-anchored** generation root the node resolved itself (§4) —
  a proof present without a matching root, or a root without a proof, fails closed;
- each chunk decrypts under AES-256-GCM-SIV or its tag fails.

A range failing any check is a HARD failure: the node discards it, re-fetches from a different holder,
and drives that source to the bottom of the selector's ranking (§7.6). A capsule fetch carries no
per-resource proof (None/None) and self-verifies on install. This is the user-facing guarantee: **when
the dig-node pulls content from another node it verifies its merkle proof AND its on-chain anchor** — a
malicious or hostile peer mix can never forge content.

### 5.4 Redirect-on-miss vs fetch-through

When the node receives a read for content it does not hold, it consults the DHT and, if a holder
exists, does ONE of two things — never a silent 404 while a provider exists:

- **REDIRECT (default).** Answer `-32008` `CONTENT_REDIRECT` whose `error.data.redirect` names the
  holder(s): `{ content: {store_id, root[, retrieval_key]}, providers: [{peer_id, addresses:[{host,
  port, kind}]}], redirect_depth: u64, max_redirects: 4 }`. Cheap + stateless; the node does not fetch.
- **FETCH-THROUGH (`DIG_NODE_ON_MISS=fetch`).** Pull the resource via §5.3 (verified), cache it, and
  serve it directly. On fetch failure, fall back to the redirect.

**Bounded hops (no loops).** `REDIRECT_HOP_CAP = 4`. The redirect carries `redirect_depth` +
`max_redirects`; a caller echoes `redirect_depth` on its re-request; a request already at/over the cap
is answered with the plain not-found. A node MUST NOT redirect a caller to itself (its own `peer_id`
is excluded). The redirect is a READ-TIER response — it exposes no peer/write/control surface.

### 5.6 Background capsule backfill (read-triggered warm-up)

When a resource read for a concrete `(store_id, root)` is satisfied **from another node** — i.e. the
node missed locally and answered with a redirect (§5.4) or a fetch-through — the node SHOULD, in the
background, ALSO pull the WHOLE `.dig` capsule for that generation and cache it, so the NEXT read of
that store is served locally. This turns a one-off remote read into a durable local copy without the
user (or the caller) opting the store into a subscription (§6).

- **Configurable, default ON.** Controlled by `DIG_NODE_BACKFILL_ON_MISS`; only an explicit falsy
  value (`off`/`0`/`false`/`no`) disables it. Distinct from `DIG_NODE_ON_MISS` (redirect vs.
  fetch-through for the CURRENT read) — backfill is the behind-the-scenes whole-capsule warm-up that
  applies under BOTH miss modes.
- **Non-blocking + deduped.** The backfill is fire-and-forget: it spawns a detached pull and returns
  immediately, so the current read is never delayed. A burst of resource reads for the same
  not-yet-held store triggers ONE whole-capsule pull (in-flight dedup keyed `store:root`), not one per
  read. It is a no-op when backfill is disabled, when the capsule is already held, or on the
  in-process FFI consumer path (which has no peer network / upstream to pull a whole capsule from).
- **Same verification.** The pull reuses the whole-generation gap-fill (§5.1, `gap_fill_generation` →
  the authenticated §21 whole-store sync): the capsule is chain-anchored-root pinned on every serve
  (§4.2) and, when a DHT is up, announced (§6.2) — verified exactly like every other cached
  generation. A failed backfill is retried on the next miss (the in-flight slot is released).

---

## 6. Subscription management

A node's **served set** is the set of stores/capsules it actively holds, watches, syncs, and publishes
as provider records so other nodes find it as a holder.

### 6.1 What the served set is + how it is managed

- The served set is the node's **durable capsule inventory** — the modules under the cache dir
  (enumerated by `cache.listCached` / `dig.listInventory`). A capsule enters the set by being cached
  (a client read that syncs it, a §21 whole-store sync, a multi-source pull, or an explicit
  `cache.fetchAndCache`); it leaves via `cache.removeCached` / `cache.clear`.
- **`cache.fetchAndCache {store_id, root}`** is the pin/subscribe primitive: it fetches + caches a
  capsule so the node thereafter watches + serves it. **`cache.removeCached`** is the unsubscribe/evict
  primitive.

**Explicit subscription surface.** The node exposes a first-class, PERSISTED subscription set — the
stores it INTENDS to keep current — DISTINCT from the durable capsule inventory (what it currently
holds). The set lives in `<cache>/subscriptions.json` (schema-versioned `{version, stores:[64hex]}`,
atomic write, serialized by the same cross-process advisory lock as the config RMW, so two DIG
processes sharing the cache cannot lose each other's updates). Managed by three CONTROL-tier methods
(loopback / in-process ONLY, never peer-reachable — §7.4a):

- **`control.subscribe`** `{ store_id: 64hex }` → `{ subscribed: true, added: bool, store_id }` —
  start watching+syncing+serving a store, persisted across restarts. Idempotent (`added:false` when
  already subscribed). A malformed id → `-32032` `CONTROL_ERROR`.
- **`control.unsubscribe`** `{ store_id: 64hex }` → `{ subscribed: false, removed: bool, store_id }` —
  stop watching (the held modules are NOT auto-evicted; use `cache.removeCached` to reclaim).
- **`control.listSubscriptions`** → `{ subscriptions: [64hex], count: u64 }`.

The subscription set drives the proactive chain watcher (§4.3) + gap-fill (§5.1) + provider-record
publication (§6.2): a store may be subscribed BEFORE any of its modules are held (the watcher pulls
them down), and a module may be held WITHOUT a subscription (a one-off cached read). The
`cache.fetchAndCache` / `cache.removeCached` capsule primitives remain the inventory-level pin/evict
controls; subscriptions are the store-level "keep current" intent that makes the node actively seek
other nodes to pull the generations it is missing.

### 6.2 Provider-record publication (inventory → DHT)

The served set drives the node's DHT provider records so peers find it as a holder (§7.5):

- **Announce on hold.** On startup and whenever a capsule enters the served set, the node
  `announce_provider`s it at **store granularity** (`ContentId::store(store_id)`) AND **capsule
  granularity** (`ContentId::capsule(store_id, root)`) — two records per held capsule. Resource
  granularity is intentionally not announced (redundant with the capsule).
- **Withdraw on removal.** When a capsule leaves the served set, the node `withdraw_provider`s its
  records (or lets them TTL out).
- **Republish before TTL.** A maintenance loop re-announces before the record TTL so a live node's
  records never expire; it also refreshes buckets + GCs stale entries.
- **Withdraw sweep on shutdown.** On graceful shutdown the node best-effort `withdraw_all`s its
  announced records.
- Records are soft state: a record at/after its absolute `expires_at` is treated as absent.

---

## 7. P2P connectivity (dig-node ↔ dig-node)

The standalone node runs the full L7 peer network by composing the peer crates. It conforms to
`docs.dig.net/docs/protocol/peer-network.md` and the shared wire in `SYSTEM.md`.

### 7.1 Identity + transport

- Every node↔node link is **mutual TLS**; a node presents ONE stable self-signed certificate and its
  identity is `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`, derived from the presented cert on
  every link (never taken from a wire body — identity is not self-asserted).
- The standalone node derives a deterministic mTLS identity from its persistent 32-byte seed
  (`identity_from_seed`: an Ed25519 PKCS#8 key from the seed), so the node's `peer_id` is stable across
  restarts. The identity seed is the same §21 seed used for authenticated sync (§5.2). If no seed is
  available the peer network is disabled (the HTTP read path still serves).
- The mTLS peer-RPC listener requires a client certificate (`rustls` `CERT_REQUIRED`, a
  `PeerIdClientVerifier` that derives `peer_id` from the leaf, no CA chain).
- The in-process FFI path opens NO peer network and NO listener (§1.2).

### 7.2 Peer-network bring-up + status

The OS-service bring-up (`dig-node run` / the Windows SCM entrypoint) calls `spawn_peer_network`
unless `DIG_PEER_NETWORK` is `off`/`0`/`false`; the in-process FFI host never does (§1.2). Startup
(`spawn_peer_network` → `run_peer_network`) proceeds in order:
1. derive the deterministic mTLS identity from the seed;
2. spawn the chain-watch + generation gap-fill loop over the subscribed store set (§4.3, §5.1)
   **FIRST**, INDEPENDENTLY of the pool/DHT — the proactive pull path is the authenticated §21
   whole-store sync, which needs neither, so a failed (or unavailable) P2P bring-up MUST NOT disable
   autonomous sync;
3. bring up the dig-gossip connected pool + relay introducer registration (relay via `DIG_RELAY_URL`,
   default `wss://relay.dig.net:9450`), and a background task that refreshes pool status (~10 s);
4. bring up the dig-dht content-location DHT (bootstrap from the gossip pool), and announce the held
   inventory (§6.2);
5. wire the multi-source content engine (`NodeContent`) to the DHT + the selector (fed by pool churn),
   and install the DHT inventory-refresh hook (so a gap-filled generation is announced immediately,
   §6.2);
6. install the Ctrl-C graceful-shutdown hook (DHT `withdraw_all` sweep);
7. bind the mTLS peer-RPC listener dual-stack on `[::]:{DIG_PEER_PORT}` (§7.3) and enter the accept
   loop, one mTLS session → yamux mux per peer;
8. bring up dig-pex (peer-exchange engine + pool feeder + tick loop).

Steps 3–8 are best-effort and gated on the P2P layer coming up; step 2 (autonomous sync) is not. In
the pre-launch state, the DIG network genesis is a placeholder, so the gossip config is rejected and
steps 3–8 do not start — the node still watches the chain and proactively gap-fills (step 2) and
serves the HTTP read path.

`control.peerStatus` reports a snapshot: `{ running: bool, peer_id: 64hex|null, network_id: string,
relay: { url, reserved: bool }, connected_peers: u64, last_error: string|null }`. Bring-up is
best-effort — a failure logs, leaves `control.peerStatus` "not running", and the HTTP read path still
serves.

### 7.3 Address family — IPv6-first, IPv4-fallback (HARD RULE, `CLAUDE.md` §5.2)

All peer communication is **IPv6-first, IPv4 fallback**, at three points (mechanics in `crate::net`):

- **Listener bind (dual-stack).** The mTLS peer-RPC listener MUST bind `[::]:{port}` as a **dual-stack**
  socket: `IPV6_V6ONLY` is explicitly cleared (`set_only_v6(false)`) before `listen`, so ONE socket
  accepts native IPv6 AND IPv4 (via IPv4-mapped) on the same port. It MUST NOT bind `0.0.0.0`
  (IPv4-only, drops IPv6) and MUST NOT leave `IPV6_V6ONLY` at its OS default. `SO_REUSEADDR` is set. An
  explicit IPv4 bind address is left unchanged.
- **Advertised addresses.** The node advertises its real, directly-dialable candidates — in its DHT
  provider record and in `dig.getNetworkInfo` — ordered **IPv6-first**: a global-unicast IPv6 address
  (when the host has one) precedes the IPv4 fallback. The wildcard bind address (`[::]`/`0.0.0.0`) is
  NOT dialable and MUST NEVER be advertised; `dig.getNetworkInfo.listen_addr` reports the primary
  (IPv6-preferred) dialable candidate, never the wildcard. A candidate is advertisable only if
  routable: an IPv6 candidate MUST NOT be loopback, unspecified, link-local (`fe80::/10`), unique-local
  (`fc00::/7`), or IPv4-mapped; an IPv4 candidate MUST NOT be loopback, unspecified, link-local
  (`169.254.0.0/16`), or broadcast (RFC-1918 private IPv4 IS advertisable — a LAN peer is reachable
  there). A NAT'd node with no routable address advertises no direct candidate and relies on the
  relay-coordinated tiers; it MUST NOT substitute a wildcard or bogus candidate. Loopback candidates
  (`::1` then `127.0.0.1`) are advertised ONLY when `DIG_NODE_ADVERTISE_LOOPBACK` is truthy
  (`1`/`true`/`yes`/`on`) — off by default.
- **Dialing (happy-eyeballs, IPv6-preferred).** When dialing a discovered peer the node MUST pass the
  peer's FULL candidate list to `dig_nat::PeerTarget::with_addrs` (which orders it IPv6-first); it MUST
  NOT collapse the peer to a single address. dig-nat then tries IPv6 candidate(s) first and falls back
  to IPv4 only on IPv6 failure/timeout. A contact with no dialable candidate becomes a `relay_only`
  target reached via the relay-coordinated tiers.

### 7.4 Peer-RPC method surface (over the mTLS mux)

Requests are length-prefixed JSON frames over dig-nat logical streams: a `u32` big-endian length prefix
+ a JSON body, byte-identical framing to the dig-nat/relay control messages and the DHT wire; a control
frame is bounded (64 KiB cap; a length over the cap is rejected, never allocated). A frame is
classified by its fields: `method` present → JSON-RPC; `length` present (no `method`) → range stream;
`items` present → availability; `type ∈ {find_node,find_providers,add_provider,ping}` → DHT;
`type ∈ {pex_*}` → PEX. The node serves:

- **`dig.getNetworkInfo`** — the node's own posture: `{ peer_id, network_id, listen_addr,
  reflexive_addr, candidate_addresses, reachability, relay }`; `candidate_addresses` is the IPv6-first
  advertised list (§7.3), `listen_addr` its first entry.
- **`dig.getPeers`** — the live connected pool (peer discovery), each `{ peer_id, addresses:[{host,
  port, kind ∈ direct|reflexive|mapped|relay}], network_id, last_seen, via }`.
- **`dig.announce`** — a peer announces `{ peer_id: 64hex, addresses: [...] }`; result `{ accepted:
  bool, known_peers: u64 }`. Error `-32602` on bad params.
- **`dig.getAvailability`** — batch answer for queried `items` (store / root / resource granularity),
  positionally aligned with the request; per item `{ available: bool, roots?: [64hex] (store
  granularity), total_length?: u64, chunk_count?: u64, complete?: bool (root/resource granularity) }`.
  The `items` count is CAPPED at **512** (items past the cap are not answered; the result array is
  aligned to the answered prefix) and the local inventory is snapshotted ONCE per batch, so an
  N-item batch does one directory walk, not N (audit #179).
- **`dig.listInventory`** — the node's held capsules (`{ store_id?, limit? }` → stores, or the roots
  for a given store). Best-effort discovery; `dig.getAvailability` is the authoritative per-item check.
- **`dig.fetchRange`** — one range frame of a served resource/capsule (the caller streams by requesting
  successive ranges). Frame: `{ offset, length, bytes: base64, complete }`; the first frame (offset 0)
  additionally carries `total_length`, `chunk_lens`, `chunk_index`, `inclusion_proof`, `root`. Errors
  `-32004` (not held), `-32007` (bad range), `-32008` (redirect on miss when holders located).
- **The four DHT methods** `find_node` / `find_providers` / `add_provider` / `ping` (§7.5), dispatched
  to the content-location DHT, folding the mTLS-verified caller into the routing table.
- **The four PEX messages** `pex_handshake` / `pex_snapshot` / `pex_delta` / `pex_error` (§7.7).

All of these are PEER/CONTROL tier — reachable only over mTLS, never on the anonymous read listener.

### 7.4a Peer-surface method allowlist (mandatory authorization boundary)

The mTLS peer surface exposes an **allowlist**, not the full RPC dispatch. The peer client-cert
verifier accepts ANY well-formed self-signed leaf (key-is-identity, no CA), so a peer that completes
the handshake has only proven "I hold the key for some `peer_id`" — NOT "I am authorized to
administer this node." The node MUST therefore route only the following methods to its dispatch when
a JSON-RPC frame arrives over the peer surface, and MUST answer every other method with `-32601`
(method not found) **before** any dispatch (so a mutation method never executes):

**Peer-reachable (allowlisted):** `dig.getContent`, `dig.getAvailability`, `dig.listInventory`,
`dig.fetchRange`, `dig.getNetworkInfo`, `dig.getPeers`, `dig.announce`, `dig.getAnchoredRoot`,
`dig.getCollection`, `dig.listCollectionItems` (plus the DHT + PEX frame families above, which are
classified by shape, not the `method` field).

**NOT peer-reachable (loopback / in-process ONLY, answered `-32601` on the peer surface):** every
`cache.*` method (`cache.getConfig`, `cache.setCapBytes`, `cache.clear`, `cache.listCached`,
`cache.removeCached`, `cache.fetchAndCache`), every `control.*` method (`control.peerStatus`,
`control.subscribe`, `control.unsubscribe`, `control.listSubscriptions`), and `dig.stage`. These
mutate node state, read attacker-chosen local paths, or expose local configuration, and are reachable
only from the loopback admin server / in-process FFI dispatch.

Adding a method to the allowlist is a deliberate security decision — it exposes that method to any
remote peer. New read/discovery methods safe for untrusted peers may be added; anything that mutates
node state or reads local resources MUST stay off the list.

### 7.5 Content-location DHT (Kademlia)

- The node LOCATES which peers hold content via `find_providers` and keeps its OWN held-inventory
  provider records current (§6.2). The DHT rides the SAME dig-nat mTLS transport (a `NatDhtTransport`
  adapter); there is no unauthenticated DHT channel. Each outbound DHT RPC is one dial + one logical
  stream bounded by a per-RPC timeout (default 5 s); a dial/stream/parse failure or timeout is treated
  as "that peer is unreachable" and the lookup walks on.
- Content-key derivation (frozen contract, `peer-network.md §4c`): `content_key = SHA-256(tag ‖
  canonical bytes)` with tag `0x01` store (`store_id`), `0x02` root/capsule (`store_id ‖ root`), `0x03`
  resource (`store_id ‖ root ‖ retrieval_key`). A node's DHT id IS its `peer_id`; distance is XOR;
  bucket = `255 − leading_zeros(distance)`. `find_providers` always returns `closer` contacts so an
  iterative lookup keeps converging. The `Contact`/`ProviderRecord` address shapes are byte-compatible
  with `dig.getPeers` addresses.

### 7.6 Source selection + download execution

- **Peer selector.** Between DHT discovery and download execution sits `dig-peer-selector`, the
  self-optimizing decision + learning layer. Of the providers `find_providers` returns, its `select`
  ranks the subset that serves content and in what order; the download executor fans byte-ranges only
  across that ranked subset with each source's recommended concurrency. Every completed range (measured
  throughput) and every failed range streams back via `record_outcome` in real time; when live sources
  run low a re-query is a `rebalance` that re-ranks the learned models and de-ranks already-active
  peers. Source choice MUST flow through the selector (`select`/`rebalance`) and every range outcome
  MUST be fed back (`record_outcome`). A range failing merkle/decrypt verification (§5.3) is a HARD
  failure that drives the source to the bottom of the ranking (below unmeasured peers); a `Banned` peer
  is ineligible. Quality is refined ONLY from measured outcomes — no input path lets a peer raise its
  own score, and observed capacity overrides advertised capacity. The selector opens no socket, runs no
  discovery, fetches no bytes; its learned state is in-memory (a restart re-learns). Its
  identity/candidate types are the SAME dig-nat/dig-dht `peer_id`/`ContentId`/`ProviderRecord`/
  `CandidateAddr`; the node maps the `dig_gossip::PoolEvent` pool-churn event into the selector's local
  `PoolEvent` shape 1:1.
- **Selector runs for SPEED mode only.** In PRIVACY mode (§8) hop selection uses the dig-onion
  privacy-aware selector, NOT `dig-peer-selector`; the exit's real fetch still uses `dig-peer-selector`
  + `dig-download` normally (§8.4).

### 7.7 Peer exchange (PEX) + relay

- **PEX.** The node embeds the `dig-pex` `PexEngine` and runs one self-identifying logical stream per
  advertising direction on each established dig-nat session (framed `u32`-BE + JSON, bounded by
  `PEX_MAX_FRAME` = 262144). The four messages are `pex_handshake` / `pex_snapshot` (≤200 first-hand
  peers) / `pex_delta` (≤50 added / ≤50 dropped) / `pex_error`. Discovered peers feed the pool as dial
  candidates (bounded per inbound batch); a PEX entry is a HINT verified only by a completed mTLS
  handshake (never impersonated as a fact). Misbehavior is strike-muted (codes 1/3/4/6 mute the
  direction; benign version/network mismatch 2/5 MUST NOT tear the connection down). The relay is the
  PEX introducer over RLY-008 (`SYSTEM.md`; peer-network.md §4d) — additive `pex_*` frames on the
  relay WebSocket, introducer-only, registration-backed.
- **Relay fallback.** Relay reachability lives inside dig-nat (the `connect()` ladder's last-resort
  tier + the persistent reservation) and dig-gossip (the introducer). The node holds no bespoke relay
  client. The relay is an untrusted forwarder; a node prefers a direct/hole-punched link and uses full
  relayed transport only when every direct strategy fails (`peer-network.md §10`). `DIG_RELAY_URL=off`
  disables the reservation.

### 7.8 Peer lifecycle + connected-pool contract

- The connected pool is owned by dig-gossip: discover → dial → maintain, with churn events
  (`PeerAdded`/`PeerRemoved`) that feed the selector registry (§7.6) and the PEX pool feeder (§7.7).
- On every inbound peer/DHT RPC the responder folds the mTLS-verified caller into its routing table —
  the caller identity MUST come from the authenticated transport, never a wire field.
- A node MAY rotate its network identity (cert → `peer_id`) to reduce long-term linkability;
  address-book entries are keyed by `IP:port`, not by `peer_id`.

---

## 8. Onion routing (privacy) — the dig-node participation contract

The node participates in the DIG onion-routing privacy layer as (a) the **requester/origin** for its
own `mode:"privacy"` reads and (b) an OPT-IN **onion relay** for others. The circuit crypto, cell
format, ntor handshake, directory record, and privacy-aware selection are defined by
`modules/crates/dig-onion/SPEC.md` and `DESIGN_ONION_ROUTING.md`; this section specifies ONLY what the
dig-node exposes and enforces, and MUST stay byte/field/flow-consistent with those documents.

**Implementation status: DESIGNED, NOT YET BUILT** in dig-node (task #194 Phase 4). §8 is the
normative target the integration is built to; the reference code today has no `mode` field, no
`dig.onion` stream, and advertises no `onion-relay` capability.

### 8.1 The mode toggle (requester side)

- `mode:"privacy"` on `dig.getContent`/`dig.fetchRange` (§2.5) routes the retrieval through a dig-onion
  telescoping circuit. The optional `privacy` object is `{ hops: 2..5 (default 3), reuse_circuit:
  bool, cover_traffic: bool }`; hops out of range → `-32022`.
- **Local-node-only (INVARIANT).** `mode:"privacy"` is honored ONLY when the caller is the node's own
  trusted local originator (loopback / `dig.local` — the browser's in-process node or the OS-service
  node on `127.0.0.1`). A node MUST NOT fetch privately on behalf of a remote/anonymous caller (that
  would hand it the caller's identity + query); a node with no trusted local originator MUST reject
  with `-32021`. So `mode` is meaningful on the caller's OWN node, never on a remote public RPC.
- **No silent downgrade (INVARIANT).** A `mode:"privacy"` request that cannot be served privately MUST
  fail with `-32020`; it MUST NOT fall back to a direct fetch. Downgrade is an explicit client/user
  choice only. **No silent upgrade:** `mode:"speed"` MUST NOT route through a circuit.
- **Integrity identical to SPEED (INVARIANT).** A private read ends in the same client-side
  verification (chain-anchored root pin + merkle inclusion + AES-256-GCM-SIV decrypt) as a fast read
  (§5.3). Privacy adds anonymity; it subtracts nothing from integrity.
- **Exit-side provider resolution (INVARIANT).** For a private fetch the node MUST NOT issue a
  content-specific DHT `find_providers` from its own node (that deanonymizes the lookup); the request
  sends `RESOLVE_PROVIDERS` down the circuit so the EXIT runs `find_providers`. The node's only DHT
  activity for privacy is the content-independent onion-directory refresh (§8.3).

### 8.2 Relay participation (opt-in)

- A node relays onion traffic ONLY when it opts in, advertising `capabilities: ["onion-relay"]` (and
  optionally `"exit"`) in `dig.getNetworkInfo` and publishing an onion identity to the directory (§8.3).
  A node that does not opt in is invisible to circuit building and behaves exactly as today; the
  in-process browser node MUST NOT relay.
- Onion cells ride a new PEER/CONTROL-tier `dig.onion` logical stream (CREATE/CREATED/EXTEND/EXTENDED/
  RELAY/RELAY_EARLY/DESTROY/PADDING cells per dig-onion §4.3) over the existing dig-nat mTLS
  `PeerConnection` — mTLS-gated, never anonymous-reachable, disjoint from the read tier. A relay learns
  only its predecessor and successor; an EXTEND causes the relay to dial the named next hop over
  dig-nat. The onion identity key `B` (X25519 static) is DISTINCT from `peer_id` (dig-onion §2.2); the
  handshake is keyed on `B`, never on `peer_id` or the mTLS session key.
- The exit relay reuses `dig-download` + `dig-peer-selector` VERBATIM to run the real fetch against
  providers (§7.6), so providers see the exit, never the requester, and need no change. The exit
  handles only DIG-layer ciphertext + proofs — it never sees plaintext or the decryption key.

### 8.3 Onion-relay directory (additive DHT namespace)

- Onion relays are discovered via a reserved additive `dig-dht` namespace: `ONION_DIRECTORY_KEY =
  SHA-256(0x04 ‖ network_id)`. Tag `0x04` is disjoint from the store/root/resource tags
  `0x01`/`0x02`/`0x03` (§7.5); adding it MUST NOT change any existing DHT semantics (backwards-compat
  HARD RULE). An onion relay `announce_provider`s under this key while it offers the capability; its
  record carries its IPv6-first candidates plus the additive extension `{ onion_key, onion_key_prev,
  capacity_class, caps, attest }` (dig-onion §5). A cold node bootstraps its first relay set from
  `relay.dig.net`'s introducer (RLY-005), then transitions to DHT-sourced discovery.
- **Anti-forgery.** The directory record is self-signed by the relay's `peer_id` cert; the node MUST
  discard a record whose `attest` does not verify and MUST confirm `onion_key` ownership via the ntor
  `AUTH` check before routing through the relay.

### 8.4 Hop selection boundary

- Circuit hops MUST be chosen by the dig-onion privacy-aware selector (uniform-cohort within
  eligibility filters, guard-pinned entry, path-diverse by `/16`·`/32` group), NOT `dig-peer-selector`
  — the quality optimizer deanonymizes circuits (`DESIGN_ONION_ROUTING.md §7.3`). `dig-peer-selector`
  is used only at the exit→provider leg (§8.2).

### 8.5 Security boundary (summary; full threat model in dig-onion §9 / DESIGN §7)

Privacy mode provides unlinkability of a content read to the reader's network identity against a
PARTIAL adversary. DIG is STRONGER than Tor on exit tampering (the exit handles only chain-verifiable
ciphertext — cannot read or forge, only withhold) and closes the DHT-lookup leak (exit-side
resolution). It does NOT defend against a global timing adversary; Sybil is the primary residual risk
(cost-raised by guards + path diversity + directory anti-forgery, not eliminated). An implementation
MUST NOT oversell the guarantee (dig-onion §9).

---

## 9. State machine / lifecycle

```
                 ┌─────────────┐
   Node::from_env│  CONSTRUCT  │  resolve+lock cache dir; load §21 identity seed (best-effort);
                 │             │  read DIG_NODE_UPSTREAM; build the anchored-root resolver
                 └──────┬──────┘
      standalone ┌──────┴──────────────┐ in-process (FFI)
                 ▼                      ▼
        ┌─────────────────┐   ┌──────────────────────────┐
        │ PEER-NET BRING-  │   │  CONSUMER-ONLY            │
        │ UP (§7.2)        │   │  no listener/DHT/PEX/relay │
        │ identity→pool→    │   │  p2p_content never set     │
        │ DHT→announce→     │   │  no chain-watch/gap-fill   │
        │ engine→watch→     │   └──────────┬────────────────┘
        │ listener→PEX      │              │
        └───────┬───────────┘              │
                ▼                          ▼
        ┌──────────────────────────────────────────────┐
        │  SERVING  — read surface up (loopback/public);  │
        │  per read: resolve anchored root (§4) → serve   │
        │  local | sync (§5.2) | multi-source pull (§5.3) │
        │  | redirect/fetch-through (§5.4) | proxy         │
        │  ─ WATCHING each SUBSCRIBED store's root (§4.3)  │
        │  ─ GAP-FILLING missing generations (§5.1)        │
        │  ─ republishing provider records (§6.2)          │
        └───────┬──────────────────────────────────────────┘
                ▼ Ctrl-C
        ┌──────────────────────────────────────────────┐
        │  SHUTDOWN — DHT withdraw_all sweep; drain      │
        └──────────────────────────────────────────────┘
```

A read is always gated on the anchored-root pin (§4) before any serve path. The peer network is
best-effort: a bring-up failure leaves the read path serving with the peer network reported
"not running".

---

## 10. Configuration + defaults

All configuration is via environment (flags/`config.json` override where noted; precedence for the
cache cap is `config.json` > env > default).

| Variable | Meaning | Default |
|---|---|---|
| `DIG_NODE_PORT` | loopback HTTP read-surface port | `9778` |
| `DIG_PEER_PORT` | mTLS peer-RPC listen port (dual-stack `[::]`) | `9444` |
| `DIG_NODE_UPSTREAM` | §21 host base for sync + read proxy fallback | `https://rpc.dig.net/` |
| `DIG_NODE_COINSET` | coinset API base for chain reads | `Coinset::mainnet()` (api.coinset.org) |
| `DIG_NODE_CACHE` | override the shared cache dir | per-OS `DigNode/cache` (§3.4) |
| `DIG_NODE_CACHE_CAP` | on-disk cache cap (bytes) | `DEFAULT_CACHE_CAP` = 1 GiB (floor 64 MiB) |
| `DIG_NODE_PIN` | anchored-root pin enforcement (`off`/`0`/`false` disables) | enforced (fail-closed) |
| `DIG_NODE_ON_MISS` | `fetch`/`fetch-through` ⇒ fetch-through on miss, else redirect | redirect |
| `DIG_NODE_BACKFILL_ON_MISS` | background-pull the whole `.dig` capsule after a resource read from another node (§5.6); `off`/`0`/`false`/`no` disables | on |
| `DIG_NODE_WATCH_INTERVAL` | chain-watch poll interval (seconds) over the subscribed store set (§4.3) | `30` (floor `1`) |
| `DIG_PEER_NETWORK` | `off`/`0`/`false` disables the peer network (read path only) | on |
| `DIG_NETWORK_ID` | network id for peer discovery / handshake scope | `DIG_MAINNET` |
| `DIG_RELAY_URL` | relay endpoint (`off`/`disabled` disables the reservation) | `wss://relay.dig.net:9450` |
| `DIG_NODE_ADVERTISE_LOOPBACK` | advertise loopback candidates when no routable address (§7.3) | off |
| `DIG_WALLET_WC_PROJECT_ID` | WalletConnect project id (persisted in `config.json`) | unset |
| onion opt-in flag (target) | opt in as an `onion-relay` (§8.2) | off |

---

## 11. Security properties

- **Provider-blind at rest + on the wire.** Stored capsules and served windows are ciphertext +
  merkle proofs; the serve host key is local/ephemeral. A LOCAL node MAY decrypt for its own consumer
  (the user's machine); the served wire stays ciphertext + proof.
- **Chain is the authority (fail-closed).** No content is served under a root not confirmed on-chain
  (§4.2); a compromised upstream cannot select the served generation.
- **Never trust a peer's bytes.** Every pulled range is verified against the chain-anchored merkle root
  before use or serving (§5.3); a bad source is detected and routed around.
- **mTLS-authenticated peer identity.** All node↔node traffic is mTLS with
  `peer_id = SHA-256(SPKI DER)`, derived from the presented cert; no unauthenticated peer channel; the
  boundary invariant keeps every write/peer/control surface off the anonymous read tier (§2.1).
- **Peer authorization is an allowlist, not just authentication.** The peer client-cert verifier
  accepts any well-formed self-signed leaf, so "authenticated" means only "some `peer_id`". The peer
  JSON-RPC surface therefore exposes ONLY the §7.4a allowlist and answers `-32601` for every
  management/mutation method (`cache.*`, `control.*`, `dig.stage`) — those are loopback/in-process
  only. Peer-triggered chain fanout is bounded (`launcher_ids` ≤ 10,000; §2.3.1) and the `dig.stage`
  directory walk is bounded (§2.3.2), so no peer-reachable call amplifies into unbounded work.
- **Bounded connection + stream concurrency.** The mTLS accept loop caps concurrent accepted
  CONNECTIONS at a global semaphore (permit taken before the handshake, so half-open/slowloris
  handshakes count), and each connection caps its concurrent in-flight STREAMS per-connection. Past
  either cap the connection/stream is SHED (dropped), never queued — a peer cannot spawn unbounded
  tasks / hold unbounded FDs + TLS sessions.
- **Authenticated writes.** §21 push/write is mTLS + per-request BLS-signed (`SYSTEM.md`
  per-request auth); §21 whole-store sync stamps the same signed headers (§5.2).
- **Onion (target).** The onion identity key is distinct from `peer_id`; the requester is hidden from
  providers + any single relay; integrity is identical to SPEED; the guarantee is a partial-adversary
  one, not global (§8.5).

---

## 12. Conformance

A reimplementation of `dig-node` conforms iff:

- The **read-tier wire** (`dig.getContent` window/chunk object: `ciphertext`/`root`/`complete`/
  `next_offset`/`inclusion_proof`/`chunk_lens`, 3 MiB windows, `ContentResponse` backward-compatible
  decode) matches `rpc.dig.net` / the digstore client byte-for-byte (`SYSTEM.md` "JSON-RPC 2.0 read
  methods"; docs.dig.net dig-rpc).
- The **anchored-root pin** fails closed with `-32005` on chain error / no confirmed generation / root
  mismatch, uniform with the CLI clone/pull pin (`SYSTEM.md` "Anchored-root pin").
- The **dual-transport boundary** holds: no peer/write/config method reachable without mTLS (`-32601`
  on the anonymous tier); content read reachable with none (`SYSTEM.md` "Dual-transport RPC tiers";
  peer-network.md §0/§7a).
- The **peer-RPC framing, DHT wire, PEX wire, and mTLS `peer_id` derivation** match the peer crates
  byte-for-byte (`dig-nat`, `dig-dht`, `dig-pex`, `dig-gossip`; peer-network.md §4c/§4d/§6/§7;
  `SYSTEM.md` shared-contract map). The `Contact`/`ProviderRecord`/`CandidateAddr`/`dig.getPeers`
  address shapes are byte-compatible; DHT content keys use tags `0x01`/`0x02`/`0x03`.
- **IPv6-first** (§7.3) holds on every peer-comms surface (bind, advertise, dial) — the ecosystem HARD
  RULE (`CLAUDE.md` §5.2).
- Source choice for SPEED mode flows through **`dig-peer-selector`** (`select`/`rebalance` +
  `record_outcome`), with the `dig_gossip::PoolEvent`→selector `PoolEvent` mapping field-identical.
- The **redirect-on-miss** contract (`-32008`, `redirect_depth`/`max_redirects=4`, no self-redirect,
  bounded hops) matches peer-network.md §9a.
- **Onion participation (target)** matches `dig-onion/SPEC.md` + `DESIGN_ONION_ROUTING.md`: the `mode`
  field + `-32020`/`-32021`/`-32022`, the `dig.onion` PEER/CONTROL stream, the `onion-relay` capability
  + `0x04` additive directory namespace, the local-node-only + no-downgrade + exit-side-resolution +
  integrity-identical invariants, and hop selection by the privacy-aware selector (NOT
  `dig-peer-selector`).

A change to any behaviour in this document MUST update this SPEC in the same unit of work, and — for a
shared contract (the read wire, the peer/DHT/PEX wire, the anchored-root pin, the `mode` field, the
`dig.onion` stream, the `0x04` namespace) — the corresponding `SYSTEM.md` / docs.dig.net / peer-crate
entries in the same unit of work (release-first for shared contracts, `CLAUDE.md` §4.1/§4.2).
