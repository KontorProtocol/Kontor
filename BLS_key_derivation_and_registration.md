# BLS key derivation + registration

This document specifies how Kontor wallets derive a BLS12-381 keypair and produce the two registration proofs that bind it to a Bitcoin Taproot (x-only) identity.

## Goals

- **Key separation**: BLS keys MUST be derived from a **different BIP-32 path** than Bitcoin Taproot keys (BIP-86) to avoid cross-protocol key reuse.
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

### 1.2 Kontor BLS derivation key (separate from Bitcoin)

Kontor’s BLS derivation MUST use a distinct BIP-32 purpose to enforce key separation:

- `m/12381'/coin_type'/account'/change/address_index`
  - mainnet: `coin_type = 0`
  - testnet: `coin_type = 1`

Default for examples/test vectors:

- `m/12381'/0'/0'/0/0`

## 2) Derive BLS keypair

### 2.1 BIP-32 derivation (seed phrase)

The wallet derives a secp256k1 child private key at the Kontor BLS derivation path (`m/12381'/...`) using standard BIP-32.

### 2.2 BLS private key

Let:

- `ikm = kontor_child_secp256k1_secret_key_bytes` (32 bytes)
- `info = "KONTOR_BLS_KEYGEN_V1"` (UTF-8 bytes)

Derive the BLS secret key using the IETF BLS KeyGen procedure as implemented by `blst`:

- `bls_sk = blst::min_sig::SecretKey::key_gen(ikm, info)`

### 2.4 BLS public key

- `bls_pubkey = bls_sk · G2` (96-byte compressed form)

## 3) Registration proofs (bind Taproot ↔ BLS)

Define binding prefixes:

- `SCHNORR_BINDING_PREFIX = "KONTOR_REG_XONLY_TO_BLS_V1"`
- `BLS_BINDING_PREFIX     = "KONTOR_REG_BLS_TO_XONLY_V1"`

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
- Kontor path: `m/12381'/1'/0'/0/0` (mainnet would be `m/12381'/0'/0'/0/0`)

Outputs:

- `x_only_pubkey` (hex, 32 bytes): `a4b70d13d6d48919c40a0c0ddac146b18ba1dde08bd1af2224060040c6189282`
- `bls_pubkey` (hex, 96 bytes): `b5c69f88da04d8a3aca6d47f3ee18e4a170bedd28a29ec779b33e3e72b9da8eaae5d4e0fe6af71807ad8437190e1e24315760b66670d460ecebb6457c3bc6862079e4f22f4d523c82b75aed9f3b34132c12053811dd12b2ed42393a4e1fd786e`
- `schnorr_sig` (hex, 64 bytes) (example): `a1aab3ff872e6a98671bc8f7b43ba4697a95cdb61e9431927276f5320eb033d444d65b862f6a91fd3c1be5b3d72827b6074527ff4770cbee377cf52f8c529821`
- `bls_sig` (hex, 48 bytes) (example): `ac5f8852015588bc8eaf0b92d53210d58ad51b0173b9139bd02110837cffe5550ee958a3ad4c1ed3d327deca77a0e1cc`
