# dig-chat-protocol — normative specification

The authoritative contract for the DIG Network chat message-TYPE layer. An independent
reimplementation can be built against this document alone. Normative keywords MUST / SHOULD / MAY are
used in their RFC 2119 sense.

## §1 Scope

`dig-chat-protocol` is a **pure message-type layer** riding the `dig-message` base protocol
(`dig-message = "0.5"`). It defines the chat payload types allocated in dig-message's reserved
**dig-chat band** `0x0000_0200..=0x0000_02FF` (`MessageBand::DigChat`) and registers them into a
`dig_message::MessageRegistry`. That is its entire responsibility.

This crate contains **NO cryptography**. Confidentiality, authenticity, integrity, anti-replay, and
streaming are provided by two layers ABOVE and BELOW it, not here:

- **Below (the transport seal):** `dig-message` seals every directed message end-to-end to the
  recipient key, signs it with the sender's BLS key, enforces the anti-replay window, and drives the
  streaming state machine. See the dig-message SPEC.
- **Above (the content seal):** the dig-chat application seals message content into an opaque
  `DIGCHAT1` blob (dig-chat app SPEC §4) before it is ever handed to this layer. This crate carries
  that blob as opaque bytes in `ChatMessage.envelope` and **MUST NOT parse, inspect, or transform
  it**.

This double-seal (content `DIGCHAT1` inner + `dig-message` transport outer) is why the type layer is
crypto-free: it is content-blind by construction and therefore cannot expose chat plaintext, even in
principle. This satisfies the ecosystem end-to-end-encryption invariant (**NC-1**, CLAUDE.md §5.4):
directed chat is e2e-encrypted to the recipient; a relay or node that terminates the mTLS pipe still
sees only ciphertext.

**Out of scope (deliberately, MVP one-shot shape):** conversation open/close types, a directory /
key-lookup type. A 1:1 conversation is correlation by peer DID; recipient-key resolution is a
dig-node RPC. No such types are defined here.

Cross-references: `dig-message` SPEC §4 (the type registry + bands), dig-chat app SPEC §4 (the
`DIGCHAT1` envelope), the superproject `SYSTEM.md` (the cross-repo interaction map), the
`normative-contract` skill NC-1.

## §2 Message types

Five payload types are defined, allocated **contiguously** from the base of the dig-chat band. Each is
a Chia-`Streamable` struct (§3). The id assignment is **additive-only**: an id, once assigned, is
never renumbered, removed, or repurposed; new types take the next free id in the band.

| id (`u32`) | Type | `Streamable` payload fields (in wire order) |
|---|---|---|
| `0x0000_0200` | `ChatMessage` | `message_id: Bytes32`, `envelope: Vec<u8>` |
| `0x0000_0201` | `DeliveryReceipt` | `message_id: Bytes32`, `status: u8` |
| `0x0000_0202` | `ReadReceipt` | `message_id: Bytes32` |
| `0x0000_0203` | `TypingIndicator` | `conversation_id: Bytes32`, `state: u8` |
| `0x0000_0204` | `Presence` | `state: u8` |

Field semantics:

- **`ChatMessage.envelope`** — the OPAQUE `DIGCHAT1` content seal. The sole content-bearing field in
  the layer. Carried verbatim; MAY be any length including empty; never parsed here.
- **`ChatMessage.message_id` / `DeliveryReceipt.message_id` / `ReadReceipt.message_id`** — the
  application-assigned id of the chat message a receipt refers to.
- **`DeliveryReceipt.status`** — a `DeliveryStatus` discriminant: `Delivered = 0`, `Failed = 1`.
- **`TypingIndicator.conversation_id`** — the conversation the indicator applies to.
- **`TypingIndicator.state`** — a `TypingState` discriminant: `Started = 0`, `Stopped = 1`.
- **`Presence.state`** — a `PresenceState` discriminant: `Online = 0`, `Away = 1`, `Offline = 2`.

**Enum discriminants are `u8` on the wire.** The named enums are the typed, validated view of that
`u8`. A reader MUST surface an unrecognized discriminant as a clean, typed error (`ChatEnumError`) and
MUST NOT panic. New enum variants are additive (a new discriminant); existing discriminants are never
renumbered. Because the wire carries a plain `u8`, a struct with an unknown discriminant still decodes
structurally — the value is validated only when the typed accessor (`status()` / `state()`) is called,
so an old reader tolerates a new-writer discriminant it does not recognize.

## §3 Wire determinism

Each payload is encoded with the Chia `Streamable` contract (`chia-traits` / `chia_streamable_macro`,
version `0.26`, the SAME source and version `dig-message` uses — the bytes MUST agree byte-for-byte):

- Fields are serialized in declaration order with no tags, names, or padding.
- `Bytes32` is 32 raw bytes.
- `Vec<u8>` is a 4-byte big-endian length prefix followed by the raw bytes.
- `u8` is one byte.

The encoding is therefore fully deterministic. The golden byte-vectors (§5) pin it: a change to any
committed digest is a wire-format break and MUST be an intentional, reviewed SemVer event.

## §4 Registration

`register_all(registry: &mut MessageRegistry, handler: Arc<dyn ChatHandler>) -> dig_message::Result<()>`
registers all five types into the registry, each decoding to its `Streamable` payload and dispatching
to the matching `ChatHandler` method.

- **Additive.** Registration adds the five ids without disturbing any handlers already present.
- **Duplicate-refused.** If any of the five ids is already registered, `register_all` returns
  `dig_message::MessageError::DuplicateType(id)` rather than overwriting the existing handler (SPEC §2
  additive-only). Registration is not transactional; call it once on a fresh registry.
- **Unknown-type rule (inherited from dig-message).** An id within the dig-chat band that has no
  registered handler (e.g. `0x0000_02FF`) is dispatched per `MessageRegistry::dispatch`: a
  request/stream shape returns `MessageError::UnsupportedType`, a one-shot/response shape is silently
  dropped (`Dispatch::Dropped`). Dispatch NEVER panics on an unknown type. This is the forward-
  compatibility property: an old reader keeps working when a newer sender introduces a new chat type.

## §5 Known-Answer Tests (conformance vectors)

The test suite (`tests/kat.rs`) pins the contract. All test material is derived from a hashed seed
(`SHA-256(tag ‖ counter)`), never a hard-coded literal.

1. **Golden byte-vectors** — for each of the five payloads, the deterministic on-wire encoding has a
   fixed length and a committed SHA-256 digest, and `encode → bytes → decode` round-trips byte-
   identically. Committed vectors (seed-derived fields):
   - `ChatMessage` — 76 bytes, `sha256 = 1242949e1b33fe2c73f546f132c894d3a6a118499cbc1e0d24c54dbec306a984`.
   - `DeliveryReceipt` — 33 bytes, `sha256 = e3a3d3eebc8e5eeb2fb539366ad4f9c45ec7dcfa8b7735ac38a37476fc24bcf1`.
   - `ReadReceipt` — 32 bytes, `sha256 = 5e79288de830117c1a6fa9ce8efad1ccb8ad3a699a2b71c1c74cb3c66fd79958`.
   - `TypingIndicator` — 33 bytes, `sha256 = 2a9bb74d921dfcf1863eadd79dd2041f21a51985f2c27d3f14d8b700cae8f576`.
   - `Presence` — 1 byte, `sha256 = 4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a`.
2. **Band membership** — every id's `.band()` is `MessageBand::DigChat`, and the ids are exactly
   `0x0200..=0x0204`, contiguous.
3. **Routing + duplicate refusal** — `register_all` then `dispatch` routes each id to the correctly
   decoded kind; a second `register_all` on the same registry returns `DuplicateType`; a
   pre-populated registry is left undisturbed.
4. **Unknown in-band id** — `0x02FF` follows the §4 unknown-type rule (drop / UnsupportedType), no
   panic.
5. **`DIGCHAT1` passthrough** — a `ChatMessage` round-trips an ARBITRARY opaque `envelope` (empty,
   single-byte, and `> 64 KiB` random) byte-identically — proving content-blindness.
6. **Enum reject** — an out-of-range `status` / `state` byte decodes structurally, then the typed
   accessor returns `ChatEnumError` (never a panic); valid discriminants map to their variants.

## §6 Threat notes

- **Confidentiality is delegated, twice.** Chat content confidentiality is provided by the inner
  `DIGCHAT1` seal (dig-chat app) and the outer `dig-message` transport seal. This layer's ONLY
  security obligation is to **never expose plaintext**, and it discharges that obligation
  *structurally*: it carries only opaque bytes, 32-byte ids, and small enum discriminants — there is
  no field into which chat plaintext could be placed unsealed.
- **Metadata residual (stated, not mitigated here).** `DeliveryReceipt`, `ReadReceipt`,
  `TypingIndicator`, and `Presence` carry no content, but they ARE metadata (who is talking to whom,
  when, and read/typing/presence state). They are protected only by the `dig-message` transport seal
  (mTLS pipe + e2e envelope), not by an additional content seal. A party that can read the opened
  `dig-message` payload learns this metadata. Reducing metadata exposure (e.g. sealed-sender, padding,
  cover traffic) is out of scope for this type layer and is a dig-message / dig-chat-app concern.
- **No panics on adversarial input.** Every value read off the wire (unknown type id, out-of-range
  enum discriminant, truncated payload) fails cleanly through `dig_message::MessageError` /
  `ChatEnumError`; the layer never panics on hostile input.

## §7 Conformance

An implementation conforms iff:

1. It defines exactly the five types at exactly the ids in §2, encoded per §3.
2. It reproduces every §5 golden digest byte-for-byte.
3. Its registration is additive and duplicate-refusing, and unknown in-band ids follow the §4
   unknown-type rule without panicking (§5.3, §5.4).
4. A `ChatMessage` round-trips an arbitrary opaque `envelope` byte-identically (§5.5), and it never
   parses the `envelope`.
5. Out-of-range enum discriminants are surfaced as clean errors, never panics (§5.6).
