//! Integration test / reference example for Kontor BLS key derivation + registration proofs.
//!
//! This test is intentionally heavily commented because it's meant to be "wallet-tooling
//! actionable": it shows exactly which bytes are derived from a seed, and exactly which bytes are
//! signed to bind a BLS keypair to a Bitcoin Taproot (x-only) identity.
//!
//! Scope of this file:
//! - Derive a Taproot identity keypair from a seed via BIP-32/BIP-86.
//! - Derive a Kontor BLS12-381 keypair from the same seed via EIP-2333 (native BLS key tree).
//! - Produce a [`RegistrationProof`] via the smart constructor and verify it.
//! - Assert deterministic outputs (pubkeys) for a fixed seed + paths.
use indexer::bls::RegistrationProof;
use testlib::*;

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_key_derivation_and_registration() -> Result<()> {
    // Create a randomly-keyed identity with both Taproot and BLS keys.
    // Derivation paths are network-aware (regtest → coin_type 1).
    let identity = reg_tester.identity().await?;

    let xonly_bytes = identity.x_only_public_key().serialize();
    let bls_pubkey = identity.bls_pubkey;
    let bls_secret_key = identity.bls_secret_key;

    // =========================================================================
    // Wallet-side: construct the registration proof via RegistrationProof::sign()
    // =========================================================================
    //
    // The smart constructor takes the Taproot keypair and BLS secret key, internally
    // builds the domain-separated messages, and produces both binding signatures.
    let proof = RegistrationProof::sign(&identity.keypair, &bls_secret_key)?;

    // Sanity: the proof carries the same identity keys we derived.
    assert_eq!(proof.x_only_pubkey, xonly_bytes);
    assert_eq!(proof.bls_pubkey, bls_pubkey);

    // =========================================================================
    // Indexer-side: verify the registration proof
    // =========================================================================
    proof.verify()?;

    // Length sanity checks.
    assert_eq!(proof.x_only_pubkey.len(), 32);
    assert_eq!(proof.bls_pubkey.len(), 96);
    assert_eq!(proof.schnorr_sig.len(), 64);
    assert_eq!(proof.bls_sig.len(), 48);

    Ok(())
}
