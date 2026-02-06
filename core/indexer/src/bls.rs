//! BLS12-381 registration proofs for the Kontor protocol.
//!
//! This module provides [`RegistrationProof`], the production data structure for binding a
//! Bitcoin Taproot (x-only) identity to a BLS12-381 public key.
//!
//! Two signatures form a bidirectional binding:
//! - **Schnorr** (Taproot → BLS): the Taproot key signs `sha256(prefix || bls_pubkey)`,
//!   proving the Taproot identity authorizes this BLS key.
//! - **BLS** (BLS → Taproot): the BLS key signs `prefix || xonly_pubkey`,
//!   proving possession of the BLS secret key and binding it back to the Taproot identity.
//!
//! # Architecture
//!
//! The wallet constructs signatures locally using the public message helpers
//! ([`RegistrationProof::schnorr_binding_message`], [`RegistrationProof::bls_binding_message`])
//! and constants, then submits a [`RegistrationProof`] to the indexer.
//! The indexer only calls [`RegistrationProof::verify`].

use anyhow::{Result, anyhow};
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::Message;
use blst::min_sig::{PublicKey as BlsPublicKey, Signature as BlsSignature};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Domain-separating prefix for the Schnorr binding proof (Taproot → BLS).
pub const SCHNORR_BINDING_PREFIX: &[u8] = b"KONTOR_XONLY_TO_BLS_V1";

/// Domain-separating prefix for the BLS binding proof (BLS → Taproot).
pub const BLS_BINDING_PREFIX: &[u8] = b"KONTOR_BLS_TO_XONLY_V1";

/// Hash-to-curve DST for protocol-level BLS signatures (BLS12-381 min_sig, G1).
///
/// Structured per RFC 9380 / draft-irtf-cfrg-bls-signature-05. Each segment is either
/// fixed by the curve/security requirements or a deliberate Kontor protocol choice:
///
/// **Kontor protocol choices:**
/// - `BLS_SIG` — tags this DST for signatures (the BLS spec defines separate DSTs
///   for key-gen and PoP; we don't mix them into the same domain).
/// - `BLS12381G1` — signatures live in G1 (48 bytes), pubkeys in G2 (96 bytes).
///   This is the "min_sig" scheme. Kontor chose min_sig because signatures get
///   aggregated and go on-chain (smaller = cheaper), while pubkeys live in the
///   registry where 96 bytes is acceptable.
/// - `NUL_` — basic scheme, no augmentation. The BLS spec offers three modes:
///   NUL (sign raw message), AUG (auto-prepend signer pubkey), and POP (separate
///   proof-of-possession ceremony). Kontor uses NUL because rogue key defense is
///   handled explicitly via [`RegistrationProof`], which serves as the PoP. Using
///   AUG would redundantly prepend the pubkey to every operation signature.
///
/// **Fixed by the curve / required for security:**
/// - `XMD:SHA-256` — expand-message-XMD with SHA-256; the standard hash-to-curve
///   expansion for BLS12-381.
/// - `SSWU` — Simplified SWU map-to-curve; the only map-to-curve method specified
///   for BLS12-381 G1 in RFC 9380.
/// - `RO` — random-oracle security (hash-to-curve, not encode-to-curve); required
///   for BLS signature EUF-CMA security.
///
/// Portal / storage node BLS uses *different* DSTs; those are intentionally not compatible.
pub const KONTOR_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

// ---------------------------------------------------------------------------
// RegistrationProof
// ---------------------------------------------------------------------------

/// A cryptographic proof that binds a Bitcoin Taproot identity to a BLS12-381 public key.
///
/// This is the wire-format payload a wallet submits to the indexer for registration.
/// The wallet constructs signatures locally then passes them to [`RegistrationProof::new`].
/// The indexer calls [`verify()`](RegistrationProof::verify) before assigning a registry ID.
#[derive(Clone, Debug)]
pub struct RegistrationProof {
    /// 32-byte Taproot x-only public key (BIP340 identity).
    pub x_only_pubkey: [u8; 32],
    /// 96-byte BLS public key (BLS12-381 min_sig, compressed G2).
    pub bls_pubkey: [u8; 96],
    /// 64-byte BIP340 Schnorr signature: Taproot authorizes the BLS key.
    pub schnorr_sig: [u8; 64],
    /// 48-byte BLS signature: BLS key proves possession + binds back to Taproot.
    pub bls_sig: [u8; 48],
}

impl RegistrationProof {
    // -----------------------------------------------------------------------
    // Message construction (public — wallets use these to know what to sign)
    // -----------------------------------------------------------------------

    /// Build the 32-byte Schnorr message: `sha256(SCHNORR_BINDING_PREFIX || bls_pubkey)`.
    ///
    /// Wallets sign this with the Taproot keypair to produce the Schnorr binding proof.
    pub fn schnorr_binding_message(bls_pubkey: &[u8; 96]) -> Message {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(bls_pubkey);
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        Message::from_digest_slice(&digest).expect("sha256 digest is 32 bytes")
    }

    /// Build the raw BLS message bytes: `BLS_BINDING_PREFIX || xonly_pubkey`.
    ///
    /// Wallets sign this with the BLS secret key to produce the BLS binding proof.
    /// Not pre-hashed — `blst` hashes-to-curve internally using [`KONTOR_BLS_DST`].
    pub fn bls_binding_message(xonly_pubkey: &[u8; 32]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + 32);
        msg.extend_from_slice(BLS_BINDING_PREFIX);
        msg.extend_from_slice(xonly_pubkey);
        msg
    }

    // -----------------------------------------------------------------------
    // Construction + verification
    // -----------------------------------------------------------------------

    /// Construct a registration proof from pre-computed fields.
    ///
    /// The wallet is responsible for producing the signatures locally.
    /// See [`Self::schnorr_binding_message`] and [`Self::bls_binding_message`] for the
    /// exact bytes that must be signed.
    pub fn new(
        x_only_pubkey: [u8; 32],
        bls_pubkey: [u8; 96],
        schnorr_sig: [u8; 64],
        bls_sig: [u8; 48],
    ) -> Self {
        Self {
            x_only_pubkey,
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        }
    }

    /// Verify both binding proofs using only the public data in this struct.
    ///
    /// This is the **indexer-side** operation. It:
    /// 1. Verifies the Schnorr signature against `x_only_pubkey`.
    /// 2. Validates the BLS public key (subgroup check).
    /// 3. Validates the BLS signature (subgroup check).
    /// 4. Verifies the BLS signature against `bls_pubkey`.
    pub fn verify(&self) -> Result<()> {
        let secp = Secp256k1::new();

        // 1. Verify Schnorr binding: Taproot → BLS.
        let schnorr_msg = Self::schnorr_binding_message(&self.bls_pubkey);
        let x_only_pk = XOnlyPublicKey::from_slice(&self.x_only_pubkey)
            .map_err(|e| anyhow!("invalid x-only pubkey: {e}"))?;
        let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&self.schnorr_sig)
            .map_err(|e| anyhow!("invalid schnorr signature bytes: {e}"))?;
        secp.verify_schnorr(&schnorr_sig, &schnorr_msg, &x_only_pk)
            .map_err(|e| anyhow!("schnorr binding verification failed: {e}"))?;

        // 2. Validate BLS public key (subgroup check).
        let bls_pk = BlsPublicKey::key_validate(&self.bls_pubkey)
            .map_err(|e| anyhow!("invalid BLS pubkey (subgroup check failed): {e:?}"))?;

        // 3. Validate BLS signature (subgroup check).
        let bls_sig_obj = BlsSignature::sig_validate(&self.bls_sig, true)
            .map_err(|e| anyhow!("invalid BLS signature (subgroup check failed): {e:?}"))?;

        // 4. Verify BLS binding: BLS → Taproot.
        let bls_msg = Self::bls_binding_message(&self.x_only_pubkey);
        let result = bls_sig_obj.verify(true, &bls_msg, KONTOR_BLS_DST, &[], &bls_pk, true);
        if result != blst::BLST_ERROR::BLST_SUCCESS {
            return Err(anyhow!("BLS binding verification failed: {result:?}"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::rand::RngCore;
    use bitcoin::key::{Keypair, rand};
    use blst::min_sig::SecretKey as BlsSecretKey;

    /// Helper: wallet-side signing logic for unit tests.
    fn sign_proof(keypair: &Keypair, bls_sk: &BlsSecretKey) -> RegistrationProof {
        let secp = Secp256k1::new();
        let x_only_pubkey = keypair.x_only_public_key().0.serialize();
        let bls_pubkey = bls_sk.sk_to_pk().to_bytes();

        let schnorr_msg = RegistrationProof::schnorr_binding_message(&bls_pubkey);
        let schnorr_sig = secp.sign_schnorr(&schnorr_msg, keypair).serialize();

        let bls_msg = RegistrationProof::bls_binding_message(&x_only_pubkey);
        let bls_sig = bls_sk.sign(&bls_msg, KONTOR_BLS_DST, &[]).to_bytes();

        RegistrationProof::new(x_only_pubkey, bls_pubkey, schnorr_sig, bls_sig)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());

        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        let bls_sk = BlsSecretKey::key_gen(&ikm, &[]).unwrap();

        let proof = sign_proof(&keypair, &bls_sk);
        proof.verify().unwrap();
    }

    #[test]
    fn verify_rejects_wrong_schnorr_key() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());

        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        let bls_sk = BlsSecretKey::key_gen(&ikm, &[]).unwrap();

        let mut proof = sign_proof(&keypair, &bls_sk);

        // Swap in a different x-only pubkey — Schnorr verification should fail.
        let other_keypair = Keypair::new(&secp, &mut rand::thread_rng());
        proof.x_only_pubkey = other_keypair.x_only_public_key().0.serialize();

        assert!(proof.verify().is_err());
    }

    #[test]
    fn verify_rejects_wrong_bls_key() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());

        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        let bls_sk = BlsSecretKey::key_gen(&ikm, &[]).unwrap();

        let mut proof = sign_proof(&keypair, &bls_sk);

        // Swap in a different BLS pubkey — both verifications should fail.
        let mut ikm2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm2);
        let other_bls_sk = BlsSecretKey::key_gen(&ikm2, &[]).unwrap();
        proof.bls_pubkey = other_bls_sk.sk_to_pk().to_bytes();

        assert!(proof.verify().is_err());
    }
}
