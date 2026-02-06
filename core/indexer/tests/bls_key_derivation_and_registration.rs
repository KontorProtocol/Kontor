//! Integration test / reference example for Kontor BLS key derivation + registration proofs.
//!
//! This test is intentionally heavily commented because it's meant to be "wallet-tooling
//! actionable": it shows exactly which bytes are derived from a seed, and exactly which bytes are
//! signed to bind a BLS keypair to a Bitcoin Taproot (x-only) identity.
//!
//! Scope of this file:
//! - Derive a Taproot identity keypair from a seed via BIP-32/BIP-86.
//! - Derive a Kontor BLS12-381 keypair from the same seed via EIP-2333 (native BLS key tree).
//! - Produce a [`RegistrationProof`] (Schnorr + BLS binding) and verify it.
//! - Assert deterministic outputs (pubkeys) for a fixed seed + paths.
//!
//! The test acts as the **wallet**: it derives keys, constructs signature messages using the
//! public helpers on [`RegistrationProof`], signs locally, and submits the proof. The indexer only
//! ever calls [`RegistrationProof::verify`].
use bitcoin::key::Secp256k1;
use blst::min_sig::SecretKey as BlsSecretKey;
use indexer::bls::{KONTOR_BLS_DST, RegistrationProof};
use testlib::*;

// Taproot identity key derivation (BIP-86):
//   m/86'/coin_type'/account'/change/address_index
//
// Regtest uses testnet coin_type (1). Mainnet would be coin_type (0).
const TAPROOT_PATH_REGTEST: &str = "m/86'/1'/0'/0/0";

// Kontor BLS key derivation path using EIP-2333 (native BLS12-381 key tree).
//
// EIP-2333 defines its own hierarchical key derivation for BLS12-381, operating natively on
// BLS12-381 scalars. All child derivation is hardened by design (no non-hardened children),
// so paths are written without the `'` marker.
//
// Path structure (following EIP-2334):
//   m / 12381 / coin_type / account / key_use
//
// Regtest uses testnet coin_type (1). Mainnet would be coin_type (0).
const KONTOR_BLS_PATH_REGTEST: &[u32] = &[12381, 1, 0, 0];

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_key_derivation_and_registration() -> Result<()> {
    // This test is a deterministic example that
    // asserts the derived pubkeys and verifies the binding proofs.
    //
    // Fixed seed for example generation (64 bytes).
    // In a wallet, this would be the output of BIP39 mnemonic-to-seed (optionally with a passphrase).
    let seed: [u8; 64] = core::array::from_fn(|i| i as u8);

    // Derive Taproot identity key + Kontor BLS key from the same BIP-39 seed via two separate
    // derivation schemes:
    //
    // The derivation itself lives in the regtest harness:
    // - `core/indexer/src/reg_tester.rs` → `RegTesterInner::identity_from_seed(...)`
    // - Taproot keypair: BIP-32/BIP-86 at `TAPROOT_PATH_REGTEST`
    // - BLS keypair: EIP-2333 at `KONTOR_BLS_PATH_REGTEST` (native BLS12-381 key tree)
    let identity = reg_tester
        .identity_from_seed(&seed, TAPROOT_PATH_REGTEST, KONTOR_BLS_PATH_REGTEST)
        .await?;

    // Deterministic derived identifiers (these are what wallet implementers care about):
    // - `xonly_bytes`: 32-byte Taproot x-only public key (BIP340 identity)
    // - `bls_pubkey`:  96-byte BLS public key under `min_sig`
    let xonly_bytes = identity.x_only_public_key().serialize();
    let bls_pubkey = identity
        .bls_pubkey
        .expect("identity_from_seed must set bls_pubkey");
    let bls_secret_key = identity
        .bls_secret_key
        .expect("identity_from_seed must set bls_secret_key");

    // =========================================================================
    // Wallet-side: construct the registration proof locally
    // =========================================================================
    let secp = Secp256k1::new();

    // Reconstruct the BLS secret key object from the raw bytes.
    let bls_sk = BlsSecretKey::from_bytes(&bls_secret_key)
        .map_err(|e| anyhow!("invalid derived BLS secret key bytes: {e:?}"))?;
    // Sanity: the derived secret key must correspond to the derived public key.
    assert_eq!(bls_sk.sk_to_pk().to_bytes(), bls_pubkey);

    // Proof 1: Schnorr — Taproot authorizes the BLS key.
    //
    // The wallet uses the public helper to build the exact message the indexer expects,
    // then signs it with the Taproot keypair.
    let schnorr_msg = RegistrationProof::schnorr_binding_message(&bls_pubkey);
    let schnorr_sig = secp
        .sign_schnorr(&schnorr_msg, &identity.keypair)
        .serialize();

    // Proof 2: BLS — BLS key proves possession + binds to Taproot.
    //
    // The wallet uses the public helper to build the raw message bytes, then signs
    // with the BLS secret key using the protocol DST.
    let bls_msg = RegistrationProof::bls_binding_message(&xonly_bytes);
    let bls_sig = bls_sk.sign(&bls_msg, KONTOR_BLS_DST, &[]).to_bytes();

    // Package everything into the wire-format struct.
    let proof = RegistrationProof::new(xonly_bytes, bls_pubkey, schnorr_sig, bls_sig);

    // =========================================================================
    // Indexer-side: verify the registration proof
    // =========================================================================
    proof.verify()?;

    // Length sanity checks.
    assert_eq!(proof.x_only_pubkey.len(), 32);
    assert_eq!(proof.bls_pubkey.len(), 96);
    assert_eq!(proof.schnorr_sig.len(), 64);
    assert_eq!(proof.bls_sig.len(), 48);

    // Example assertions (deterministic outputs; should match BLS_key_derivation_and_registration.md).
    assert_eq!(
        hex::encode(seed),
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    );
    // Taproot x-only pubkey (BIP-32/BIP-86 — unchanged).
    assert_eq!(
        hex::encode(xonly_bytes),
        "a4b70d13d6d48919c40a0c0ddac146b18ba1dde08bd1af2224060040c6189282"
    );
    // BLS pubkey (EIP-2333 derivation at path [12381, 1, 0, 0]).
    println!("bls_pubkey (EIP-2333): {}", hex::encode(bls_pubkey));
    assert_eq!(
        hex::encode(bls_pubkey),
        "a56dd059afccd191121b9bb8ec2ff6b9b18e302064e18faca45b6e1b38eb7c7f37130d01ead92037459663c4ff9be3d8198223658e0a0196af2fe68de58cbce9e0299c76e6ec5223791344f3bbda528b7b81dea5fd55b204027d54fa242fdcec"
    );
    assert_eq!(
        hex::encode(bls_secret_key),
        "403ec84ec266cc93809d5a4c576f9b60b44260c739202b857f24d4d47358461b"
    );

    Ok(())
}
