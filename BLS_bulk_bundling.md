BlsBulk is a **Kontor-native batching format**: many signed operations are packed into **one Bitcoin transaction**, with **one 48‑byte BLS aggregate signature**, and **indexers verify then execute**. This is directly aligned with the scalability docs’ batching model:

```
### Transaction Bundling

The most significant optimization is trustless BLS signature aggregation. ... BLS signatures can be aggregated: N signatures from N different signers compress into a single 48-byte aggregate signature. ...
1. **Users sign operations.** ... The signature commits to the operation details: target contract, function, arguments.
...
4. **Indexers verify and execute.** ... verify the aggregate signature against all (public key, message) pairs and execute each operation with its designated signer as caller.
Users do not need to trust bundlers. ... anyone can produce a valid aggregate.
```

---

### 1) Indexer responsibilities for BlsBulk (with spec/doc/feedback references)

### A. **Ingest + classify BlsBulk**

- **Detect batch payloads**: the indexer must postcard-decode the envelope bytes as a Kontor `Inst` and route `Inst::BlsBulk` to the bulk handler.
- **Keep the direct path working**: the scalability spec explicitly has *Direct* vs *Bundled* publication paths:

```
Users have two publication paths:
1. *Direct*: ... signs it with a standard Schnorr/Taproot wallet.
2. *Bundled*: the user signs a Kontor operation message with their BLS key ... A bundler aggregates ... and publishes it to Bitcoin.
...
Since operations are signed, bundlers cannot forge, edit, or redirect operations---only include or exclude them.
```

### B. **Decode the container (Postcard) with hardening limits**

- **Decode steps**:
    - postcard-decode `Inst`
    - match `Inst::BlsBulk { ops, signature }`
    - extract `ops`
- **Hardening**: enforce max payload bytes and max ops/batch to avoid DoS.
- **Why Postcard + Zstd**: explicitly described in the scalability spec’s methodology:

```
1. *Serialization*: Operations are serialized using Postcard ...
2. *Compression*: The serialized batch is compressed using Zstd at level 15 (high compression).
3. *Signature overhead*: BLS aggregate signatures add 48 bytes ...
```

### C. **Define the BlsBulk op format (WaveCall v1) and canonical signing bytes**

- **BlsBulk op (minus BinaryCall)**: a minimal v1 should be a generic call:
    - `signer_ref` (ideally a registry ID; see below)
    - `nonce` (replay protection)
    - `gas_limit` (signer cost cap)
    - `contract` (address) + `expr` (WAVE call string)
- **Canonical bytes**: define `op_bytes = postcard(op_struct)` and ensure the indexer reconstructs *exactly* the same bytes signers used.
- **Why the signature must bind to op details**: scalability doc requires signatures commit to “target contract, function, arguments”:

```
1. **Users sign operations.** ... The signature commits to the operation details: target contract, function, arguments.
...
4. **Indexers verify and execute.**
```

### D. **Signer registry + identity mapping**

BlsBulk needs a way to resolve “who signed this op” → “what BLS public key verifies it” in a **deterministic, reorg-safe** way.

- **Deterministic registry is in the docs**:
    - `Documentation/docs/consensus/scalability.mdx` describes compact registry IDs and deterministic assignment:

```
### Compact Registry IDs

Kontor maintains a deterministic registry that maps long identifiers ... to compact 4-byte numeric IDs.
When a new identifier first appears ... the indexer assigns it the next sequential ID. This is deterministic—all indexers processing the same blocks assign the same IDs.
```

- `Documentation/specs/scalability/main.typ` specifies automatic registration + rollback requirements:

```
=== Automatic Registration

When a new public key first signs a Kontor operation, the indexer automatically assigns it the next sequential registry ID. ...
=== Consistency Requirements
Registry state must be identical across all indexers:
- IDs assigned sequentially on first use
- Deterministic ...
- Reorgs require registry state rollback
```

- **Feedback constraints to incorporate**:
    - require **Proof of Possession (PoP)** for BLS keys (rogue-key defense), and use distinct domains for PoP vs operations (`KONTOR-POP-V1`, `KONTOR-OP-V1`).
    - the registry must associate x-only pubkey + BLS pubkey + integer ID (single identity).

### E. **BLS aggregate verification (must happen before execution)**

Per the docs, verification precedes execution:

```
3. **Bundlers aggregate and publish.** ...
4. **Indexers verify and execute.** ... verify the aggregate signature ...
```

Indexer responsibilities:

- **Reconstruct the exact message list** and pubkey list in the exact batch order.
- **Validate pubkeys/signatures are in the correct subgroup** (per feedback; `blst` subgroup checks must be enabled).
- **Aggregate-verify** using `blst::min_sig` (48‑byte signatures, 96‑byte pubkeys).

### F. **Replay protection**

Docs don’t prescribe the exact mechanism for batched ops replay protection, but the decision was to

- include `nonce: u64` in each op
- indexer maintains a `(signer_id, nonce)` used-set (reorg-safe rollback)

(Portal’s current system uses a `batch_id` set, but that’s Portal-specific; see below.)

### G. **Gas limit enforcement**

- `gas_limit` must be **chosen by the signer** and **included in the signed preimage**, so bundlers can’t raise execution cost after signing.
- Indexer must enforce the limit during Wasm execution (existing fuel/gas metering stays; BlsBulk just supplies per-op limits).

### H. **Deterministic execution + results indexing**

- Execute ops **sequentially in batch order** (deterministic).
- Decide semantics for failures:
    - minimal + consistent with today’s behavior: if one op fails, log and continue; state changes from failed op are rolled back (per-op savepoints).
- Ensure contract results are indexed with a stable `(tx_index, input_index, op_index)`; for batches, `op_index` should reflect **inner index** (and ideally also incorporate outer index if multiple ops exist in one tx input).

### I. **Work not yet done (required for “real” BlsBulk)**

- **Finalize BlsBulk op signing spec** (bytes + DST + fields like nonce/gas_limit).
- **Implement aggregate verification** + subgroup checks + error handling policy (reject whole batch vs partial).
- **Implement replay tables** (and reorg-safe cascade/rollback behavior).
- **Implement signer registry** (and PoP + inline registration, if you want “first bundle includes registration”).
- **Add tests**: decode limits, invalid signature, pubkey validation, replay, reorg rollback, and end-to-end portal-produced batches.

---

### 2) Portal integration requirements (and Market/Node updates)

### A. **What Portal does today (and why it differs)**

Portal currently batches via `api_calls`:

- payload is Postcard: `(batch_id, aggregated_bls_signature, bls_public_keys, instructions...)`
- signers sign legacy messages `(portal_signing_xpub, instruction)` under `HORIZON_PORTAL_BLS_DST`
- `batch_id` is the replay mechanism

```
The `api_calls` function processes a batch ... The payload contains a batch identifier, an aggregated BLS signature, and a list of instructions ...
Each signer binds their authorization ... by including the Portal's extended public key.
```

```
[
    <batch_id>,
    <aggregated_bls_signature>,
    <bls_public_keys>,
    [ [ <instruction>, <bls_public_key_index> ], [ <instruction> ], ... ]
]
...
`batch_id` ... Double SHA-256 of the instructions array ... used for replay protection
... Aggregated BLS signature over each `(portal_signing_xpub, instruction)` pair
...
The `batch_id` ... serves as the sole replay protection mechanism ...
```

And its DST is:

```
pub const BLS_DST: &[u8] = b"HORIZON_PORTAL_BLS_DST";
```

**BlsBulk differs** because it’s “users sign operations; indexers verify & execute” at the indexer layer, not “call a contract function that interprets instructions.”

### B. **Minimal Portal changes to publish BlsBulk**

Portal already uses the indexer’s compose plumbing by passing raw bytes into the envelope (so commit/reveal composition stays the same). For BlsBulk it needs to:

- **Stop wrapping into** `Inst::Call { expr: "api-calls([..])" }`.
- **Instead produce raw** `Inst::BlsBulk { ops, signature }` bytes as the envelope payload.
- **Build ops as WaveCalls** (contract address + WAVE expr), *not* legacy string-instruction tuples.

### C. **What Portal needs for *verifiable* BlsBulk (not just “execute”)**

Portal cannot manufacture signatures without private keys. So it needs cooperation from Market/Node (and potentially wallet tooling):

- **Market/Node software updates (required)**:
    - They must sign the **BlsBulk op preimage** (e.g. `postcard(CallWave { signer_ref, nonce, gas_limit, contract, expr })`) under the **BlsBulk/Kontor DST** (not `HORIZON_PORTAL_BLS_DST`).
    - They must supply `(signature, pubkey or signer_id)` back to Portal/bundler.
- **Portal/bundler responsibilities**:
    - collect signed ops
    - optionally sanity-verify each signature
    - aggregate signatures into one 48-byte aggregate
    - build the BlsBulk container
    - ensure ordering is deterministic (so everyone reconstructs the same message list)
- **Key lookup strategy must match the indexer**:
    - if BlsBulk ops carry `signer_id` (recommended), Portal must know those IDs (or include inline registrations)
    - if BlsBulk ops carry raw pubkeys, Portal includes them (bigger payload)
- **Replay protection fields**:
    - if indexer uses per-signer nonces, Portal must generate/provide nonces and ensure it doesn’t resubmit duplicates for the same signer.
- **Gas limit**:
    - Portal can suggest a default, but the signer must ultimately approve it by signing bytes that include it.

### Future iteration (inside BlsBulk):

**add `BinaryCall`**

Once BlsBulk WaveCall is stable end-to-end, add a next iteration that replaces WAVE `expr` with the spec’s compact binary call format:

- aligns with `Documentation/specs/scalability/main.typ`’s `BinaryCall` and the “registry IDs + binary encoding + zstd” stack
- yields much smaller payloads and better compression, while keeping the same high-level pipeline (Postcard + Zstd + 48-byte aggregate signature, verify then execute).

### Bundler pays gas fees

Bundler pays gas fees and charges users