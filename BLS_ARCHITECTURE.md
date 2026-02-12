### BLS architecture (Kontor)

This document specifies the BLS architecture for Kontor transaction authorization and batching. It is written to support:

- **Direct publication**: users publish a single Kontor operation secured by Bitcoin Schnorr/Taproot.
- **Bundled publication**: users sign Kontor operations with BLS; bundlers aggregate signatures and publish many operations in one Bitcoin transaction; indexers verify the aggregate and execute operations deterministically.

---

### 0) Why BLS (and why aggregation) — spec excerpts

```
Bitcoin transaction overhead dominates per-operation cost. Bundling many operations into one Bitcoin transaction amortizes this overhead across many operations. A batch of N operations pays the fixed cost once, reducing per-operation overhead from ~680 WU to ~680 / N WU. The bundle itself is published as a normal Taproot spend (Schnorr-signed by the bundle publisher), but each operation still requires an authorization signature from its signer.

Without signature aggregation, you must include N per-operation signatures (for example, Schnorr signatures) at 64 bytes each, which can dominate the payload. BLS signatures have the property that N signatures on N distinct messages can be combined into a single 48-byte aggregate, verifiable by Kontor indexers.

Crucially, BLS aggregation is trustless: any party with access to the signed operations can produce a valid aggregate.
```

Source: `../Documentation/specs/scalability/main.typ` (Optimizations → “BLS Signature Aggregation”), L128–L132

```
Users have two publication paths:
1. Direct: the user constructs a Bitcoin transaction containing a single Kontor operation and signs it with a standard Schnorr/Taproot wallet.
2. Bundled: the user signs a Kontor operation message with their BLS key and broadcasts it to one or more bundlers. A bundler aggregates many users' operations, signs the resulting Bitcoin transaction with its publisher key (the Taproot key that authorizes the spend), and publishes it to Bitcoin.
```

Source: `../Documentation/specs/scalability/main.typ` (Optimizations → “BLS Signature Aggregation”), L134–L137

```
Optimizations 2–4 are completely invisible to users. Direct publication uses a standard Taproot spend secured by Bitcoin Schnorr signatures, so users can publish operations with existing wallets and keys. Batching is opt-in: users sign Kontor operations with BLS (BLS12-381, as used by the Ethereum Beacon Chain since 2020), bundlers aggregate these signatures and publish them in a single Bitcoin transaction, and Kontor indexers (not Bitcoin Script) verify the aggregate.
```

Source: `../Documentation/specs/scalability/main.typ` (Introduction), L23

```
The key property of BLS is that N signatures on N distinct messages combine into a single 48-byte aggregate, verifiable in one operation.

Bitcoin does not validate the BLS signature; Kontor indexers do. Aggregation is trustless: any party with access to signed operations can produce a valid aggregate. There is no privileged aggregator role; any node can aggregate signed operations and broadcast a batch.
```

Source: `../Documentation/specs/whitepaper/main.typ` (Scalability), L157

---

### 1) Protocol objects (what exists on-chain)

Kontor messages are embedded in Bitcoin transactions via a Taproot envelope in the witness. Payload bytes are postcard-serialized.

```
Each Kontor operation is embedded in a Bitcoin transaction via Taproot witness script:
[pubkey] [OP_CHECKSIG] [OP_FALSE] [OP_IF] "kor" [OP_0] [data_pushes...] [OP_ENDIF]

pub enum Inst {
    Publish { gas_limit: u64, name: String, bytes: Vec<u8> },
    Call { gas_limit: u64, contract: ContractAddress, expr: String },
    Issuance,
}
```

Source: `../Documentation/specs/scalability/main.typ` (Baseline → “Transaction Format”), L31–L44

```
During block parsing, each Kontor indexer detects these scripts efficiently through pattern matching...
Kontor message data, embedded in the witness data of the Taproot Reveal transaction, is serialized using Postcard.
```

Source: `../Documentation/specs/whitepaper/main.typ` (Protocol → “Transaction Encoding”), L139–L140

**Implementation note**: the specs use the marker string `b"kor"` in examples; the current indexer/composer implementation uses `b"kon"` as the protocol tag.

#### A. `Inst::BlsBulk` (bundled publication)

Bundled publication is represented as a Kontor instruction variant:

- **`Inst::BlsBulk { ops, signature }`**
  - **`ops`**: ordered list of operations to execute
  - **`signature`**: the **single aggregate BLS signature** (48 bytes under `blst::min_sig`)

This document treats `Inst::BlsBulk` as the canonical Kontor-native “bundled operation” container.

---

### 2) Cryptographic domains and safety requirements

The architecture separates signature “spaces” so that no byte-string is valid as both a PoP signature and an operation signature.

- **PoP domain** (rogue-key defense): `KONTOR-POP-V1 || pubkey`
- **Operation domain** (authorization): `KONTOR-OP-V1 || op_index || nonce || operation_data`

Additionally:

- **Subgroup validation MUST be enabled** for BLS public keys and signatures (BLS12-381 cofactors).
- **Key derivation separation MUST be enforced** between Bitcoin Taproot keys and Kontor BLS keys.

```
Key separation: BLS keys MUST be derived using EIP-2333 (native BLS12-381 key tree), which is an entirely separate derivation scheme from Bitcoin's BIP-32/BIP-86 (secp256k1). This prevents cross-protocol key reuse.
```

Source: `BLS_key_derivation_and_registration.md` (Goals), L7

---

### 3) Identity model and registry (x-only ↔ BLS ↔ signer ID)

Bundled operations must map “who signed this op” → “which BLS public key verifies it” deterministically and reorg-safely.

The registry is the protocol’s canonical mapping layer:

- `signer_id` (compact numeric ID)
- `x_only_pubkey` (Bitcoin/Taproot identity)
- `bls_pubkey` (BLS authorization identity)

```
When a new public key first signs a Kontor operation, the indexer automatically assigns it the next sequential registry ID. This is deterministic: all indexers process blocks identically, so they assign the same IDs.

Registry state must be identical across all indexers:
- IDs assigned sequentially on first use
- Deterministic: all indexers derive identical mappings from the same blocks
- Reorgs require registry state rollback
```

Source: `../Documentation/specs/scalability/main.typ` (Registry → Automatic Registration / Consistency Requirements), L170–L177

#### A. Proof of Possession (PoP) — required

Rogue-key defense requires PoP: a BLS public key must not be admitted to the registry without proof that the submitter knows its secret key.

- PoP is a BLS signature over the PoP domain tag and the public key.
- PoP verification must include subgroup checks.
- PoP and operation signatures use distinct domain tags.

#### B. Inline registration — required

To avoid forcing a separate pre-registration transaction, bundles must support inline registration:

- A bundle includes a `new_signers` array of raw BLS pubkeys (and any required proofs).
- Operations may reference signers via `BundleIndex(n)` into `new_signers`.
- Indexer processes registrations first (verifying PoPs, assigning IDs), then resolves `BundleIndex` references before executing operations.

---

### 4) Operation format and signing bytes

Bundled publication is only safe if signers and indexers construct **exactly the same message bytes** for verification.

#### A. Minimal v1 operation (WaveCall)

A minimal v1 op should be a generic call that is easy to execute end-to-end:

- `signer_ref` (ideally a registry ID; may be `BundleIndex` for inline registration)
- `nonce` (replay protection)
- `gas_limit` (signer cost cap)
- `contract` (address) + `expr` (WAVE call string)

Canonical bytes:

- define `op_bytes = postcard(op_struct)`
- define signing preimage with explicit domain separation and `op_index` binding:
  - `msg = "KONTOR-OP-V1" || op_index || nonce || gas_limit || op_bytes`

Spec rationale for “operation authorization is separate from publisher Schnorr signing”:

```
The bundle itself is published as a normal Taproot spend (Schnorr-signed by the bundle publisher), but each operation still requires an authorization signature from its signer.
```

Source: `../Documentation/specs/scalability/main.typ` (Optimizations → “BLS Signature Aggregation”), L128

#### B. Future iteration: `BinaryCall`

After the WaveCall v1 is stable end-to-end, replace WAVE `expr` with the spec’s compact binary call format (`BinaryCall`) and apply compression as part of the full scalability stack.

---

### 5) Bundlers (permissionless integration)

Bundlers are generic off-chain services that aggregate signed operations and publish bundles on Bitcoin. Bundling is trustless: any party with access to signed operations can produce a valid aggregate.

Bundler responsibilities:

- **Ingest signed operations** from users (any transport: p2p gossip, API, mempool scanning, etc.).
- **Preserve ordering deterministically** (the ordering is part of what gets verified).
- **Aggregate signatures** into one 48-byte signature.
- **Publish to Bitcoin** using the standard Kontor Taproot envelope, with payload `Inst::BlsBulk`.
- **Pay BTC miner fees** for the publish transaction.
- **Charge users a bundling fee** according to the protocol’s bundler economics model.

Bundler economics (spec excerpt):

```
The bundling fee f_bun(t) compensates bundlers for Bitcoin block space costs...
Bundling is trustless: any party with access to signed operations can produce a valid aggregate.
```

Source: `../Documentation/specs/scalability/main.typ` (Bundler Economics), L303–L307

---

### 6) Indexers (verification + deterministic execution)

Indexers must process `Inst::BlsBulk` deterministically, verifying before executing.

#### A. Decode and pre-validate

- postcard-decode `Inst`
- match `Inst::BlsBulk { ops, signature }`
- enforce hardening limits (max ops/bundle, signature length, payload bytes)

#### B. Resolve signers

- resolve each op’s signer reference to a BLS public key
- process inline registrations first (PoP verification + ID assignment), then resolve `BundleIndex` references
- registry mapping must be deterministic and reorg-safe

#### C. Replay protection

- include `nonce: u64` in each op preimage
- maintain a `(signer_id, nonce)` used-set (reorg-safe rollback)

#### D. Aggregate verification

Verification must occur before execution:

- reconstruct message list and public key list in exact op order
- validate public keys and signatures are in the correct subgroup
- `aggregate_verify` the single 48-byte signature against all `(pubkey, message)` pairs

#### E. Execute

- execute ops sequentially in bundle order (deterministic)
- enforce per-op `gas_limit` (must be signer-chosen and signed over)
- record results with stable `(tx_index, input_index, op_index)` where `op_index` is the inner op index

Rollback + determinism requirements (spec excerpts):

```
When a function returns an Err or panics, all storage modifications are rolled back...
```

Source: `../Documentation/specs/whitepaper/main.typ` (Sigil Smart Contracts → “Error Handling and Rollback”), L295

```
Kontor runs contracts in Wasmtime with threading, SIMD, and floating-point non-determinism disabled...
```

Source: `../Documentation/specs/whitepaper/main.typ` (Sigil Smart Contracts → “Deterministic Execution”), L305–L307

---

### 7) Serialization + compression (full stack vs v1)

The full scalability stack includes Postcard serialization and Zstd compression; v1 `Inst::BlsBulk` uses Postcard and intentionally defers compression to a later, uniform layer.

```
Serialization: Operations are serialized using Postcard (a compact binary format based on variable-length integer encoding).
Compression: The serialized batch is compressed using Zstd at level 15 (high compression).
Signature overhead: BLS aggregate signatures add 48 bytes plus 4 bytes per unique signer in the batch (for signer ID lookup).
```

Source: `../Documentation/specs/scalability/main.typ` (Benchmarks → Methodology), L219–L223

