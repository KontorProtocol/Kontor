## BLS Architecture (Kontor Indexer)

This document describes **how BLS + batching is implemented today** in the Kontor indexer (`core/indexer/`), including the on-chain formats, signing preimages, registry model, and execution semantics.

It is written to be **wallet/bundler-tooling actionable** and intentionally calls out where the current `Documentation/` specs lag the implementation.

### Scope

- **In scope**: protocol-level BLS aggregation for batched contract calls, signer registry + binding proofs, KBL1 container format, replay protection, and `BinaryCall` execution.

### High-level overview

Kontor supports two publication paths:

- **Direct (legacy)**: a single `Inst` is included in the Taproot envelope and authorized by the Bitcoin Schnorr signature on the input.
- **Batched (KBL1)**: multiple operations are compressed into a `KBL1` payload and authorized by a **single 48-byte BLS aggregate signature** over the signed operations in the batch.

```mermaid
flowchart TD
  TxInput[TaprootScriptPathInput] --> Envelope[OP_FALSE OP_IF "kon" OP_0 ... OP_ENDIF]
  Envelope --> Payload[PayloadBytes]
  Payload -->|starts_with KBL1| Kbl1Batch[KBL1Batch]
  Payload -->|else| DirectInst[postcard Inst]

  DirectInst --> SchnorrAuth[BitcoinSchnorrAuth]
  Kbl1Batch --> BlsAuth[BlsAggregateAuth]

  SchnorrAuth --> Runtime[RuntimeExecute]
  BlsAuth --> Runtime
```

### 1) Cryptography primitives and domain separation

#### Protocol-level BLS (indexer)

- **Curve/Scheme**: BLS12-381 `min_sig` (`blst::min_sig`)
  - **Signature size**: 48 bytes
  - **Public key size**: 96 bytes
- **Common encodings**:
  - Public key hex: 192 hex chars (96 bytes)
  - Signature hex: 96 hex chars (48 bytes)
- **DST used for protocol BLS signatures** (constant):
  - `core/indexer/src/bls.rs`: `KONTOR_BLS_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"`
  - This matches the standard “hash-to-curve” DST used by many BLS ecosystems.
- **Subgroup checks**:
  - Enforced via `PublicKey::key_validate(...)` and `Signature::sig_validate(..., true)` in `core/indexer/src/bls.rs`.

#### Portal / Storage Node BLS (not protocol BLS)

Portal and Storage Node also use `blst::min_sig`, but with **their own DSTs**:

- Portal: `HORIZON_PORTAL_HTTP_SIG` and `HORIZON_PORTAL_BLS_DST` in `Horizon-Portal/src/config/constants.rs`
- Storage node: same constants in `Kontor-Storage-Node/src/bls.rs`

Portal/Storage-node APIs frequently transport BLS keys/signatures as **hex strings**, but the protocol batch format uses **raw bytes** (Postcard + raw BLS bytes).

These are **intentionally not compatible** with protocol batching. This DST separation prevents cross-protocol signature replay.

### 2) Bitcoin envelope encoding

Indexers parse Taproot script-path spends that match the envelope pattern:

- `... OP_CHECKSIG OP_FALSE OP_IF "kon" OP_0 <data pushes...> OP_ENDIF`

Implementation:

- `core/indexer/src/block.rs`: the envelope tag is **`"kon"`**.
- The data pushes are concatenated into a single payload byte string.

The payload is interpreted as:

- **KBL1 batch** if it starts with `b"KBL1"` (`batch::is_kbl1_payload`)
- **Legacy Inst** otherwise (Postcard `Inst` in `indexer-types`)

### 3) Canonical signer identity: registry IDs

#### Goals

- **Single canonical signer identity across both paths** (direct Schnorr and batched BLS)
- Deterministic ID assignment and rollback safety across reorgs

#### Database model

`core/indexer/src/database/sql/schema.sql`:

- `signer_registry(id INTEGER PRIMARY KEY, xonly_pubkey BLOB UNIQUE NOT NULL, bls_pubkey BLOB UNIQUE NULL, first_seen_height, first_seen_tx_index, ...)`
  - `bls_pubkey` is **nullable** until a BLS key is bound.
- `signer_nonces(signer_id, nonce, height, tx_index, input_index, op_index, PRIMARY KEY(signer_id, nonce), ...)`
  - `nonce` is stored as `u64::to_le_bytes()` in a BLOB (see `database/queries.rs`).
- Both tables reference `blocks(height)` with `ON DELETE CASCADE` to ensure rollback safety.

#### X-only-first assignment

`core/indexer/src/database/queries.rs`:

- `assign_or_get_signer_id_by_xonly(...)`
  - Inserts a new row with `(xonly_pubkey, bls_pubkey=NULL)` on first x-only appearance.
- `assign_or_get_signer_id_by_xonly_and_bls(...)`
  - Binds `bls_pubkey` to an existing x-only row (or inserts a new row with both), with conflict checks.

#### Contract-visible identity

`core/indexer-types/src/lib.rs`:

- `Signer::RegistryId { id: u32, id_str: String }` is used as the canonical identity inside contracts.
- The displayed string is `@<id>` (e.g. `@123`).

The indexer canonicalizes direct-path signers to `RegistryId` before execution:

- `core/indexer/src/reactor/mod.rs` (`Op::Publish`, `Op::Call`, `Op::Issuance`)

### 4) Binding proofs for `RegisterSigner` (rogue-key defense)

To prevent rogue-key / key-substitution issues when binding a BLS key to a Taproot x-only key, Kontor requires **two proofs**:

1) **Schnorr binding signature** (x-only → BLS)
- Prefix: `b"KONTOR_REG_XONLY_TO_BLS_V1"`
- Message: `sha256(prefix || bls_pubkey_96)` as a BIP340 `secp256k1::Message`
- Signature: 64-byte Schnorr signature under the x-only key

2) **BLS binding signature** (BLS → x-only)
- Prefix: `b"KONTOR_REG_BLS_TO_XONLY_V1"`
- Message: `prefix || xonly_pubkey_32` (bytes)
- Signature: 48-byte BLS signature under the BLS key, using `KONTOR_BLS_DST`

Implementation:

- `core/indexer/src/signer_registry.rs`: `verify_registration_proofs(...)` and `register_signer(...)`

### 5) KBL1 container format

`core/indexer/src/batch.rs` defines the batch container used on-chain.

#### Byte layout

```
0..4     "KBL1"
4..8     compressed_len: u32 little-endian
8..(8+compressed_len)   zstd(compressed_ops_bytes)
(...)..end              aggregate_signature: [u8; 48]
```

The decompressed stream is capped to **8 MiB**:

- `MAX_DECOMPRESSED_BATCH_BYTES = 8 * 1024 * 1024`

#### Decompressed ops stream format

The decompressed bytes are **a concatenation of Postcard-encoded `BatchOpV1` values**, back-to-back (no explicit length prefix per op).

Indexers parse this with `postcard::take_from_bytes::<BatchOpV1>(...)` and record the exact byte ranges (`op_ranges`) so that signature verification can use the **original bytes**.

### 6) Batch operations (`BatchOpV1`)

`core/indexer/src/batch.rs`:

#### `BatchOpV1::RegisterSigner`

```text
RegisterSigner {
  xonly_pubkey: [u8; 32],
  bls_pubkey: Vec<u8>,    // must be 96 bytes
  schnorr_sig: Vec<u8>,   // must be 64 bytes
  bls_sig: Vec<u8>,       // must be 48 bytes
}
```

- Not covered by the batch aggregate signature.
- Authenticated by its binding proofs.

#### `BatchOpV1::Call` (BinaryCall in-batch)

```text
Call {
  signer: SignerRefV1,
  nonce: u64,
  gas_limit: u64,
  contract_id: u32,
  function_index: u16,
  args: Vec<u8>,
}
```

`SignerRefV1` supports:

- `Id(u32)`: stable registry ID
- `XOnly([u8; 32])`: allows signing a call without the bundler predicting the assigned ID

### 7) Signing preimages

#### Message-level domain separation for call ops

Even though the BLS DST is constant, Kontor adds a **message prefix** for call operations:

- `core/indexer/src/batch.rs`: `KONTOR_KBL1_CALL_MESSAGE_PREFIX = b"KONTOR_OP_V1"`

For a single `BatchOpV1::Call`, the message to sign is:

```text
message = b"KONTOR_OP_V1" || op_bytes
```

Where:

- `op_bytes` is the **exact Postcard bytes of the `Call` op as it appears in the decompressed stream**
- Indexers must not “re-serialize” the op for verification; they must use the original bytes

Implementation:

- `batch::kbl1_message_for_op_bytes(op_bytes)`
- `reactor/mod.rs` slices `decoded.decompressed_ops[range]` for each call op and prefixes it

#### Aggregate signature

Bundlers collect valid individual signatures and aggregate them into a single 48-byte signature.

Indexers verify using:

- `core/indexer/src/bls.rs`: `verify_aggregate_signature(aggregate_sig, public_keys, messages)`

### 8) Batch processing semantics (signature-atomic)

The indexer implements **signature-atomic batching**:

- If aggregate signature verification cannot be performed or fails: **reject the entire batch with no side effects**
- If aggregate verification succeeds: **apply and execute ops sequentially**, and individual failures do not roll back earlier ops

Implementation:

- `core/indexer/src/reactor/mod.rs` under `Op::Batch`

#### Verification phase (no DB writes)

1) Decode KBL1 payload (header, zstd decompress, parse ops, compute `op_ranges`)
2) Pre-validate all `RegisterSigner` proofs in-memory, building a map:
   - `in_batch_bls_by_xonly: [u8;32] -> [u8;96]`
3) For each `Call` op:
   - Resolve the BLS pubkey for verification:
     - Prefer registry `bls_pubkey` if already bound
     - Else fall back to `in_batch_bls_by_xonly`
   - Build `message = b"KONTOR_OP_V1" || op_bytes` using the original `op_bytes` range
4) Verify the aggregate signature over all (pk, message) pairs

If any call’s signer pubkey cannot be resolved (no bound key and no valid in-batch registration), the batch is rejected (it is “not verifiable”).

If the batch contains **zero `Call` ops** (only `RegisterSigner` ops), the current indexer treats it as invalid (“contains no signed ops”) and applies **no side effects**. TODO: this does not sound correct!

#### Execution phase (DB writes + runtime execution)

After aggregate verification succeeds:

- `RegisterSigner`: applied via `signer_registry::register_signer` (may fail; failure is per-op)
- `Call`:
  - The runtime context `op_index` is the **0-based index of `Call` ops within the batch** (it does not count `RegisterSigner` ops).
  1) Resolve `signer_id` (creating an x-only-only row on first use if needed)
  2) Require the signer has a **bound** BLS pubkey in the registry for execution
  3) Reserve `(signer_id, nonce)` in `signer_nonces` (replay protection)
     - Reservation is not rolled back if execution fails
  4) Execute `Runtime::execute_binary(...)`

### 9) `BinaryCall` execution (runtime)

`core/indexer/src/runtime/binary.rs` implements the in-batch binary execution path.

#### Contract resolution

- `contract_id: u32` is resolved through the contract registry to a `ContractAddress`:
  - `get_contract_address_from_id(...)`

#### Function resolution (deterministic)

- `function_index: u16` is mapped to an export name by decoding the contract’s embedded WIT world.
- Eligible exports are those whose first parameter is either:
  - `borrow<proc-context>` (“procedure” exports), or
  - `borrow<view-context>` (“view” exports),
  - excluding `"init"`.
- Index ordering is stable:
  - all proc exports first (in WIT declaration order), then all view exports (in WIT declaration order).

This makes `function_index` deterministic across indexers because it is derived from the contract bytes on-chain.

#### Args encoding

`args: Vec<u8>` is interpreted as **Postcard-encoded tuple of parameters** for the target export, *excluding* the leading context parameter.

Example (from `core/indexer/tests/kbl1_batch_integration.rs`):

- `token.mint(ctx, amt: decimal)`
- Encode:
  - `decimal_amt = (r0, r1, r2, r3, sign_variant_index)`
  - `args = postcard::to_allocvec(&(decimal_amt,))`

The runtime performs type-directed decoding into `wasmtime::component::Val` by using the component’s runtime type info.

### 10) Direct Schnorr path compatibility

Direct path remains supported:

- Envelope contains Postcard `Inst` (publish/call/issuance), with WAVE text for calls.
- Authorization is via the Bitcoin Schnorr signature (Taproot input spend).

Before execution, the indexer canonicalizes the signer to a registry ID so contracts see the same signer identity across both paths:

- `Signer::XOnlyPubKey("...")` → `Signer::RegistryId { id, id_str: "@<id>" }`

### 11) Differences vs current `Documentation/` specs (as of 2026-01)

The following deltas are important for implementers:

- **Envelope tag**:
  - Specs currently show `"kor"` in the Taproot envelope.
  - Indexer implementation uses **`"kon"`** (`core/indexer/src/block.rs`).
- **BinaryCall shape**:
  - Scalability spec shows `BinaryCall { signer_id, contract_id, function_index, args }`.
  - Indexer’s batched call op includes **`nonce`** and **`gas_limit`**, and supports `SignerRefV1::XOnly` in addition to `SignerRefV1::Id`.
- **Signed message preimage**:
  - Indexer signs `b"KONTOR_OP_V1" || op_bytes` where `op_bytes` are the original Postcard bytes of the `Call` op (no `op_index` in the preimage).
- **“48 bytes + 4 bytes per unique signer” benchmark language**:
  - The current indexer batch format does not include an explicit “unique signer id list” trailer; signer IDs (or x-only pubkeys) live inside each call op.
  - The authoritative performance model should be updated to reflect the exact on-chain format if needed.

### 12) Implementation map (code pointers)

- **BLS verification**: `core/indexer/src/bls.rs`
- **KBL1 format + ops**: `core/indexer/src/batch.rs`
- **Signer binding proofs + registry binding**: `core/indexer/src/signer_registry.rs`
- **DB schema**: `core/indexer/src/database/sql/schema.sql`
- **DB queries (registry + nonces)**: `core/indexer/src/database/queries.rs`
- **Batch verification + signature-atomic execution**: `core/indexer/src/reactor/mod.rs`
- **BinaryCall runtime execution**: `core/indexer/src/runtime/binary.rs`
- **Taproot envelope parsing**: `core/indexer/src/block.rs`
- **Integration tests**: `core/indexer/tests/kbl1_batch_integration.rs`

### 13) Open items / future work

- **Wallet derivation path**: specify a Kontor-specific BIP-32 path for BLS keys and publish test vectors (to align wallet tooling, Portal, and storage node).
- **Composer support for batching**: extend the transaction composer (`core/indexer/src/api/compose.rs` + related `compose` API/types) to build `kon` Taproot envelope transactions whose payload is a `KBL1` batch (compressed ops + aggregate signature), so bundlers (Portal, storage node, wallets) can publish BLS batches on-chain.
- **Docs alignment**: update `Documentation/specs/whitepaper/main.typ` and `Documentation/specs/scalability/main.typ` to reflect:
  - `"kon"` envelope tag
  - current KBL1 + `BatchOpV1::Call` shape
  - current signing preimages
- **Optional size optimization**: add a compact in-batch reference for newly registered signers (e.g., bundle-local index) while keeping the signed preimage independent of batch structure (trustless rebundling).
