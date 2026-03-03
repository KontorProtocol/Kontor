# BLS key derivation + registration

This document specifies how Kontor wallets derive a BLS12-381 keypair and produce the two registration proofs that bind it to a Bitcoin Taproot (x-only) identity.

## Goals

- **Key separation**: BLS keys MUST be derived using **EIP-2333** (native BLS12-381 key tree), which is an entirely separate derivation scheme from Bitcoin's BIP-32/BIP-86 (secp256k1). This prevents cross-protocol key reuse.
- **Determinism**: given the same seed and paths, all implementations MUST derive identical BLS keys.
- **Verifiability**: the registry can verify both proofs and then assign a compact numeric `signer_id`.

## 1) Derivation paths (normative)

### 1.1 Taproot key (Bitcoin wallet identity)

Taproot (x-only) keypair uses BIP-86:

- `m/86'/coin_type'/account'/change/address_index`
  - mainnet: `coin_type = 0`
  - testnet: `coin_type = 1`

Default for examples/test vectors:

- `m/86'/0'/0'/0/0`

### 1.2 Kontor BLS key (EIP-2333, separate from Bitcoin)

Kontor's BLS derivation MUST use **EIP-2333**, which defines a hierarchical key derivation scheme native to BLS12-381. EIP-2333 operates on BLS12-381 scalars directly (unlike BIP-32, which is secp256k1-specific). All EIP-2333 child derivation is hardened by design, so paths are written without the `'` marker.

Path structure (following EIP-2334):

- `m / 12381 / coin_type / account / key_use`
  - mainnet: `coin_type = 0`
  - testnet: `coin_type = 1`

Default for examples/test vectors:

- `m/12381/0/0/0` (mainnet)
- `m/12381/1/0/0` (testnet/regtest)

## 2) Derive BLS keypair

### 2.1 EIP-2333 master key derivation

The wallet derives a BLS12-381 master secret key from the BIP-39 seed using EIP-2333:

- `master_sk = blst::min_sig::SecretKey::derive_master_eip2333(seed)`

### 2.2 EIP-2333 child key derivation

Traverse the path by deriving child keys at each index:

- `sk = master_sk`
- For each `index` in `[12381, coin_type, account, key_use]`:
  - `sk = sk.derive_child_eip2333(index)`
- `bls_sk = sk` (the final child key)

### 2.3 BLS public key

- `bls_pubkey = bls_sk · G2` (96-byte compressed form)

## 3) Registration proofs (bind Taproot ↔ BLS)

Define binding prefixes:

- `SCHNORR_BINDING_PREFIX = "KONTOR_XONLY_TO_BLS_V1"`
- `BLS_BINDING_PREFIX     = "KONTOR_BLS_TO_XONLY_V1"`

Define the BLS domain separation tag (DST) for protocol-level BLS signatures:

- `KONTOR_BLS_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"`

### 3.1 Proof 1: Taproot authorizes the BLS key (Schnorr)

Wallet constructs:

- `msg = sha256(SCHNORR_BINDING_PREFIX || bls_pubkey)`

Then signs `msg` with the **Taproot key** (BIP-86 path) using BIP340 Schnorr:

- `schnorr_sig: [u8; 64]`

### 3.2 Proof 2: BLS key possesses secret + binds back to Taproot (BLS)

Wallet constructs:

- `msg = BLS_BINDING_PREFIX || xonly_pubkey` (raw bytes, no hash)

Then signs with the derived BLS secret key using `KONTOR_BLS_DST` as DST:

- `bls_sig: [u8; 48]`

## 4) Registration payload (what user submits)

```
{
  x_only_pubkey: 32 bytes,
  bls_pubkey:    96 bytes,
  schnorr_sig:   64 bytes,
  bls_sig:       48 bytes
}
```

## 5) Example

Reference implementation lives in:

- `core/indexer/tests/bls_key_derivation_and_registration.rs`

The deterministic derivation outputs below (`x_only_pubkey`, `bls_pubkey`) should match the reference implementation.

### Example 1

- `seed` (hex, 64 bytes): `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`
- Taproot path: `m/86'/1'/0'/0/0` (mainnet would be `m/86'/0'/0'/0/0`)
- Kontor BLS path (EIP-2333): `[12381, 1, 0, 0]` (mainnet would be `[12381, 0, 0, 0]`)

Outputs:

- `x_only_pubkey` (hex, 32 bytes): `a4b70d13d6d48919c40a0c0ddac146b18ba1dde08bd1af2224060040c6189282`
- `bls_pubkey` (hex, 96 bytes): TODO — regenerate after first test run with EIP-2333 derivation
- `schnorr_sig` (hex, 64 bytes) (example): TODO — regenerate (depends on new bls_pubkey)
- `bls_sig` (hex, 48 bytes) (example): TODO — regenerate (depends on new bls_pubkey)
