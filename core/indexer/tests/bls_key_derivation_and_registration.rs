//! Integration test / reference example for Kontor BLS key derivation + registration proofs.
//!
//! This test is intentionally heavily commented because it’s meant to be “wallet-tooling
//! actionable”: it shows exactly which bytes are derived from a seed, and exactly which bytes are
//! signed to bind a BLS keypair to a Bitcoin Taproot (x-only) identity.
//!
//! Scope of this file:
//! - Derive a Taproot identity keypair from a seed via BIP-32/BIP-86.
//! - Derive a Kontor BLS12-381 keypair from the same seed via a *separate* BIP-32 path.
//! - Produce *two* binding proofs (Schnorr + BLS) and verify them.
//! - Assert deterministic outputs (pubkeys) for a fixed seed + paths.
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::Message;
use blst::min_sig::{PublicKey as BlsPublicKey, Signature as BlsSignature};
use blst::min_sig::SecretKey as BlsSecretKey;

use testlib::*;

// Taproot identity key derivation (BIP-86):
//   m/86'/coin_type'/account'/change/address_index
//
// Regtest uses testnet coin_type (1). Mainnet would be coin_type (0).
const TAPROOT_PATH_REGTEST: &str = "m/86'/1'/0'/0/0";

// Kontor BLS key derivation path (project convention; MUST be separate from Taproot's BIP-86 path):
//   m/12381'/coin_type'/account'/change/address_index
//
// This separation prevents cross-protocol key reuse (Taproot Schnorr keys vs. Kontor BLS keys).
const KONTOR_BLS_DERIVATION_PATH_REGTEST: &str = "m/12381'/1'/0'/0/0";

// Domain-separating prefixes for the two registration proofs.
//
// We use two proofs to bind a Taproot x-only identity to a BLS public key:
// - Schnorr (x-only -> BLS pubkey): proves the Taproot identity authorizes this BLS key.
// - BLS (BLS -> x-only): proves possession of the BLS secret key and binds back to the x-only key.
//
// These prefixes make the signing preimages unambiguous and non-interchangeable.
const SCHNORR_BINDING_PREFIX: &[u8] = b"KONTOR_REG_XONLY_TO_BLS_V1";
const BLS_BINDING_PREFIX: &[u8] = b"KONTOR_REG_BLS_TO_XONLY_V1";

// Protocol-level BLS signatures use the BLS12-381 `min_sig` scheme:
// - signatures are 48 bytes (G1)
// - public keys are 96 bytes (G2)
//
// This DST is the "hash-to-curve" domain separation tag used by `blst` when hashing messages to G1.
// (Portal / storage node BLS uses *different* DSTs; those are intentionally not compatible.)
const KONTOR_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

// SHA256 helper used to turn arbitrary bytes into a 32-byte Schnorr message.
fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(bytes).to_byte_array()
}

// Construct the 32-byte message for the Schnorr binding proof.
//
// BIP340 Schnorr signs a 32-byte "message". How you derive that 32-byte value from higher-level
// structured data is protocol-defined. Kontor uses:
//
//   msg = sha256(prefix || payload)
//
// where payload is the 96-byte BLS pubkey being bound.
fn schnorr_message(prefix: &[u8], payload: &[u8]) -> Message {
    let mut preimage = Vec::with_capacity(prefix.len() + payload.len());
    preimage.extend_from_slice(prefix);
    preimage.extend_from_slice(payload);
    let digest = sha256_digest(&preimage);
    Message::from_digest_slice(&digest).expect("sha256 digest is 32 bytes")
}

// Construct the message bytes for the BLS binding proof.
//
// We do NOT pre-hash here. Instead we pass these bytes to `blst`, and `blst` hashes-to-curve using
// `KONTOR_BLS_DST` (see `verify(true, msg, dst, ...)` below).
fn bls_binding_message(xonly_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + xonly_pubkey.len());
    msg.extend_from_slice(BLS_BINDING_PREFIX);
    msg.extend_from_slice(xonly_pubkey);
    msg
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_key_derivation_and_registration_vector_1_print() -> Result<()> {
    // NOTE: The name is legacy ("vector_1_print"). This test is now a deterministic example that
    // asserts the derived pubkeys and verifies the binding proofs.
    //
    // Fixed seed for example generation (64 bytes).
    // In a wallet, this would be the output of BIP39 mnemonic-to-seed (optionally with a passphrase).
    let seed: [u8; 64] = core::array::from_fn(|i| i as u8);

    // Secp256k1 context for creating/verifying BIP340 Schnorr signatures.
    let secp = Secp256k1::new();

    // Derive Taproot identity key + Kontor BLS key from the same seed via two *separate* BIP-32 paths.
    //
    // The derivation itself lives in the regtest harness:
    // - `core/indexer/src/reg_tester.rs` → `RegTesterInner::bls_identity_from_seed(...)`
    // - Taproot keypair: derived at `TAPROOT_PATH_REGTEST` (BIP-86)
    // - BLS keypair: derived at `KONTOR_BLS_DERIVATION_PATH_REGTEST` and then fed into `blst` keygen
    let bls_identity = reg_tester
        .bls_identity_from_seed(
            &seed,
            TAPROOT_PATH_REGTEST,
            KONTOR_BLS_DERIVATION_PATH_REGTEST,
        )
        .await?;

    // Deterministic derived identifiers (these are what wallet implementers care about):
    // - `xonly_bytes`: 32-byte Taproot x-only public key (BIP340 identity)
    // - `bls_pubkey`:  96-byte BLS public key under `min_sig`
    let xonly_bytes = bls_identity.identity.x_only_public_key().serialize();
    let bls_pubkey = bls_identity.bls_pubkey;

    // Registration proof: Taproot binds to BLS pubkey.
    //
    // This is the "x-only -> BLS" authorization:
    // the Taproot signer produces a Schnorr signature over `sha256(prefix || bls_pubkey_96)`.
    let schnorr_msg = schnorr_message(SCHNORR_BINDING_PREFIX, &bls_pubkey);
    let schnorr_sig = secp.sign_schnorr(&schnorr_msg, &bls_identity.identity.keypair);
    // Verify immediately to ensure the proof is well-formed.
    secp.verify_schnorr(
        &schnorr_sig,
        &schnorr_msg,
        &bls_identity.identity.x_only_public_key(),
    )
    .map_err(|e| anyhow!("schnorr binding signature failed verification: {e}"))?;
    let schnorr_sig = schnorr_sig.serialize();

    // Registration proof: BLS binds back to x-only pubkey.
    //
    // This is the "BLS -> x-only" possession/binding proof:
    // the BLS signer signs `prefix || xonly_pubkey_32` using the protocol DST.
    let bls_sk = BlsSecretKey::from_bytes(&bls_identity.bls_secret_key)
        .map_err(|e| anyhow!("invalid derived BLS secret key bytes: {e:?}"))?;
    // Sanity: the derived secret key must correspond to the derived public key.
    assert_eq!(bls_sk.sk_to_pk().to_bytes(), bls_pubkey);
    let bls_msg = bls_binding_message(&xonly_bytes);
    let bls_sig = bls_sk.sign(&bls_msg, KONTOR_BLS_DST, &[]).to_bytes();
    // Parse + validate derived BLS objects. In production paths we require subgroup checks.
    let bls_pk = BlsPublicKey::key_validate(&bls_pubkey)
        .map_err(|e| anyhow!("invalid derived BLS pubkey bytes: {e:?}"))?;
    let bls_sig_obj = BlsSignature::sig_validate(&bls_sig, true)
        .map_err(|e| anyhow!("invalid derived BLS signature bytes: {e:?}"))?;
    // Verify with subgroup checks enabled (the final `true`).
    let result = bls_sig_obj.verify(true, &bls_msg, KONTOR_BLS_DST, &[], &bls_pk, true);
    assert_eq!(result, blst::BLST_ERROR::BLST_SUCCESS);

    // Length sanity checks (example values are filled in after first run).
    assert_eq!(xonly_bytes.len(), 32);
    assert_eq!(bls_pubkey.len(), 96);
    assert_eq!(schnorr_sig.len(), 64);
    assert_eq!(bls_sig.len(), 48);

    // Example assertions (deterministic outputs; should match BLS_key_derivation_and_registration.md).
    assert_eq!(
        hex::encode(seed),
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    );
    assert_eq!(
        hex::encode(xonly_bytes),
        "a4b70d13d6d48919c40a0c0ddac146b18ba1dde08bd1af2224060040c6189282"
    );
    assert_eq!(
        hex::encode(bls_pubkey),
        "b5c69f88da04d8a3aca6d47f3ee18e4a170bedd28a29ec779b33e3e72b9da8eaae5d4e0fe6af71807ad8437190e1e24315760b66670d460ecebb6457c3bc6862079e4f22f4d523c82b75aed9f3b34132c12053811dd12b2ed42393a4e1fd786e"
    );

    Ok(())
}
