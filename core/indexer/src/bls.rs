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
//! - **Wallet-side**: [`RegistrationProof::new`] takes a Taproot keypair and BLS secret key,
//!   produces both binding signatures, and returns the proof.
//! - **Indexer-side**: [`RegistrationProof::verify`] validates both signatures using only public data.

use anyhow::{Result, anyhow};
use bitcoin::Network;
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::Message;
use blst::min_sig::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
};
use indexer_types::{Inst, Insts};
use std::collections::HashMap;

use crate::runtime::Runtime;
use crate::runtime::registry::api::get_entry_by_id;

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

/// Compressed BLS12-381 MinSig signature length in bytes.
pub const BLS_SIGNATURE_BYTES: usize = 48;

/// Hard cap on number of operations per aggregate bundle.
pub const MAX_BLS_BULK_OPS: usize = 10_000;

/// Hard cap on total signed message bytes per aggregate bundle.
pub const MAX_BLS_BULK_TOTAL_MESSAGE_BYTES: usize = 1_000_000;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Return the coin_type index for BIP-44 / EIP-2334 derivation paths.
///
/// Mainnet = 0, everything else (Testnet / Signet / Regtest) = 1.
fn coin_type(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        _ => 1,
    }
}

/// Taproot identity key derivation path (BIP-86) for the given network.
///
/// `m/86'/<coin_type>'/0'/0/0`
pub fn taproot_derivation_path(network: Network) -> String {
    format!("m/86'/{coin}'/0'/0/0", coin = coin_type(network))
}

/// Kontor BLS key derivation path (EIP-2333) for the given network.
///
/// EIP-2333 defines hierarchical key derivation for BLS12-381, operating natively
/// on BLS scalars. All child derivation is hardened by design.
///
/// Path structure (following EIP-2334): `m / 12381 / <coin_type> / <account> / <key_use>`
pub fn bls_derivation_path(network: Network) -> Vec<u32> {
    vec![12381, coin_type(network), 0, 0]
}

/// Derive a BLS12-381 secret key from a BIP-39 seed using EIP-2333.
pub fn derive_bls_secret_key_eip2333(seed: &[u8], path: &[u32]) -> Result<BlsSecretKey> {
    let mut sk = BlsSecretKey::derive_master_eip2333(seed)
        .map_err(|e| anyhow!("EIP-2333 master key derivation failed: {e:?}"))?;
    for &index in path {
        sk = sk.derive_child_eip2333(index);
    }
    Ok(sk)
}

// ---------------------------------------------------------------------------
// Private message construction helpers
// ---------------------------------------------------------------------------

/// Build the 32-byte Schnorr message: `sha256(SCHNORR_BINDING_PREFIX || bls_pubkey)`.
fn schnorr_binding_message(bls_pubkey: &[u8; 96]) -> Message {
    let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
    preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
    preimage.extend_from_slice(bls_pubkey);
    let digest = sha256::Hash::hash(&preimage).to_byte_array();
    Message::from_digest_slice(&digest).expect("sha256 digest is 32 bytes")
}

/// Build the raw BLS message bytes: `BLS_BINDING_PREFIX || xonly_pubkey`.
///
/// Not pre-hashed — `blst` hashes-to-curve internally using [`KONTOR_BLS_DST`].
fn bls_binding_message(xonly_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + 32);
    msg.extend_from_slice(BLS_BINDING_PREFIX);
    msg.extend_from_slice(xonly_pubkey);
    msg
}

// ---------------------------------------------------------------------------
// Aggregate verification — BLS pubkey resolution and signature checking
// ---------------------------------------------------------------------------

/// Resolved signer_id → x_only_pubkey mapping returned by [`verify_aggregate`]
/// so the block handler can look up signers without redundant registry calls.
pub type SignerMap = HashMap<u64, String>;

struct SignerResolver {
    pk_cache: HashMap<u64, BlsPublicKey>,
    signer_map: SignerMap,
}

impl SignerResolver {
    fn new() -> Self {
        Self {
            pk_cache: HashMap::new(),
            signer_map: HashMap::new(),
        }
    }

    async fn resolve(&mut self, runtime: &mut Runtime, signer_id: u64) -> Result<BlsPublicKey> {
        if let Some(pk) = self.pk_cache.get(&signer_id) {
            return Ok(*pk);
        }

        let entry = get_entry_by_id(runtime, signer_id).await?;
        let entry = entry.ok_or_else(|| anyhow!("unknown signer_id {signer_id}"))?;
        self.signer_map
            .insert(signer_id, entry.x_only_pubkey.clone());
        let raw_bytes = entry
            .bls_pubkey
            .ok_or_else(|| anyhow!("signer_id {signer_id} has no BLS pubkey registered"))?;

        let pk = BlsPublicKey::key_validate(&raw_bytes)
            .map_err(|e| anyhow!("invalid BLS pubkey (subgroup check failed): {e:?}"))?;
        self.pk_cache.insert(signer_id, pk);
        Ok(pk)
    }
}

/// Verify the BLS aggregate signature on an `Insts` envelope.
///
/// Returns a `SignerMap` (signer_id → x_only_pubkey) so the caller can resolve
/// signers for execution without redundant registry lookups.
pub async fn verify_aggregate(runtime: &mut Runtime, insts: &Insts) -> Result<SignerMap> {
    let agg = insts
        .aggregate
        .as_ref()
        .ok_or_else(|| anyhow!("verify_aggregate called on non-aggregate Insts"))?;

    if insts.ops.is_empty() {
        return Err(anyhow!("aggregate must contain at least one operation"));
    }
    if insts.ops.len() > MAX_BLS_BULK_OPS {
        return Err(anyhow!(
            "aggregate contains {} operations (max {})",
            insts.ops.len(),
            MAX_BLS_BULK_OPS
        ));
    }
    if agg.signer_ids.len() != insts.ops.len() {
        return Err(anyhow!(
            "signer_ids length ({}) != ops length ({})",
            agg.signer_ids.len(),
            insts.ops.len()
        ));
    }
    for inst in &insts.ops {
        match inst {
            Inst::Call { nonce: Some(_), .. } => {}
            Inst::Call { nonce: None, .. } => {
                return Err(anyhow!(
                    "aggregate path only supports Call with nonce (missing nonce)"
                ));
            }
            Inst::RegisterBlsKey { .. } => {
                return Err(anyhow!(
                    "RegisterBlsKey is not allowed in aggregate path (use direct)"
                ));
            }
            Inst::Publish { .. } => {
                return Err(anyhow!(
                    "aggregate path only supports Call with nonce (got Publish)"
                ));
            }
            Inst::Issuance => {
                return Err(anyhow!(
                    "aggregate path only supports Call with nonce (got Issuance)"
                ));
            }
        }
    }
    if agg.signature.len() != BLS_SIGNATURE_BYTES {
        return Err(anyhow!(
            "invalid aggregate signature length: expected {BLS_SIGNATURE_BYTES}, got {}",
            agg.signature.len()
        ));
    }

    let aggregate_sig = BlsSignature::sig_validate(&agg.signature, true)
        .map_err(|e| anyhow!("invalid aggregate signature bytes: {e:?}"))?;

    let mut resolver = SignerResolver::new();
    let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(insts.ops.len());
    let mut pks: Vec<BlsPublicKey> = Vec::with_capacity(insts.ops.len());
    let mut total_message_bytes: usize = 0;

    for (inst, &signer_id) in insts.ops.iter().zip(agg.signer_ids.iter()) {
        let msg = inst.aggregate_signing_message(signer_id)?;
        total_message_bytes = total_message_bytes.saturating_add(msg.len());
        if total_message_bytes > MAX_BLS_BULK_TOTAL_MESSAGE_BYTES {
            return Err(anyhow!(
                "aggregate signed message bytes exceed max {}",
                MAX_BLS_BULK_TOTAL_MESSAGE_BYTES
            ));
        }
        pks.push(resolver.resolve(runtime, signer_id).await?);
        msgs.push(msg);
    }

    let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let pk_refs: Vec<&BlsPublicKey> = pks.iter().collect();
    let verify_result =
        aggregate_sig.aggregate_verify(true, msg_refs.as_slice(), KONTOR_BLS_DST, &pk_refs, true);
    if verify_result != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(anyhow!(
            "BLS aggregate signature verification failed: {verify_result:?}"
        ));
    }

    Ok(resolver.signer_map)
}

// ---------------------------------------------------------------------------
// RegistrationProof
// ---------------------------------------------------------------------------

/// A cryptographic proof that binds a Bitcoin Taproot identity to a BLS12-381 public key.
///
/// This is the wire-format payload a wallet submits to the indexer for registration.
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
    /// Construct a registration proof by signing with both keys.
    ///
    /// This is the **wallet-side** operation. It:
    /// 1. Derives the BLS public key from the secret key.
    /// 2. Signs `sha256(SCHNORR_BINDING_PREFIX || bls_pubkey)` with the Taproot keypair.
    /// 3. Signs `BLS_BINDING_PREFIX || xonly_pubkey` with the BLS secret key.
    pub fn new(keypair: &Keypair, bls_secret_key: &[u8; 32]) -> Result<Self> {
        let secp = Secp256k1::new();
        let x_only_pubkey = keypair.x_only_public_key().0.serialize();

        let bls_sk = BlsSecretKey::from_bytes(bls_secret_key)
            .map_err(|e| anyhow!("invalid BLS secret key: {e:?}"))?;
        let bls_pubkey = bls_sk.sk_to_pk().to_bytes();

        let schnorr_msg = schnorr_binding_message(&bls_pubkey);
        let schnorr_sig = secp.sign_schnorr(&schnorr_msg, keypair).serialize();

        let bls_msg = bls_binding_message(&x_only_pubkey);
        let bls_sig = bls_sk.sign(&bls_msg, KONTOR_BLS_DST, &[]).to_bytes();

        Ok(Self {
            x_only_pubkey,
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        })
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
        let schnorr_msg = schnorr_binding_message(&self.bls_pubkey);
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
        let bls_msg = bls_binding_message(&self.x_only_pubkey);
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
    use crate::database::connection::new_connection;
    use crate::runtime::{ComponentCache, Storage};
    use bitcoin::key::rand;
    use bitcoin::key::rand::RngCore;
    use indexer_types::{AggregateInfo, ContractAddress, Inst, Insts};
    use tempfile::TempDir;

    async fn new_test_runtime() -> (Runtime, TempDir) {
        let tmp = TempDir::new().expect("tempdir");
        let conn = new_connection(tmp.path(), "test.db")
            .await
            .expect("db connection");
        let storage = Storage::builder().conn(conn).build();
        let runtime = Runtime::new(ComponentCache::new(), storage)
            .await
            .expect("runtime");
        (runtime, tmp)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());

        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        let bls_sk = BlsSecretKey::key_gen(&ikm, &[]).unwrap();

        let proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes()).unwrap();
        proof.verify().unwrap();
    }

    #[test]
    fn verify_rejects_wrong_schnorr_key() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());

        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        let bls_sk = BlsSecretKey::key_gen(&ikm, &[]).unwrap();

        let mut proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes()).unwrap();

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

        let mut proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes()).unwrap();

        // Swap in a different BLS pubkey — both verifications should fail.
        let mut ikm2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm2);
        let other_bls_sk = BlsSecretKey::key_gen(&ikm2, &[]).unwrap();
        proof.bls_pubkey = other_bls_sk.sk_to_pk().to_bytes();

        assert!(proof.verify().is_err());
    }

    #[tokio::test]
    async fn verify_aggregate_rejects_empty_bundle() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let insts = Insts {
            ops: vec![],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![],
                signature: vec![],
            }),
        };
        let err = verify_aggregate(&mut runtime, &insts)
            .await
            .expect_err("empty bundle must be rejected");
        assert!(err.to_string().contains("at least one operation"));
    }

    #[tokio::test]
    async fn verify_aggregate_rejects_wrong_signature_length() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let insts = Insts {
            ops: vec![Inst::Call {
                gas_limit: 0,
                contract: ContractAddress {
                    name: String::new(),
                    height: 0,
                    tx_index: 0,
                },
                nonce: Some(0),
                expr: String::new(),
            }],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![0],
                signature: vec![0u8; super::BLS_SIGNATURE_BYTES - 1],
            }),
        };
        let err = verify_aggregate(&mut runtime, &insts)
            .await
            .expect_err("wrong signature length must be rejected");
        assert!(
            err.to_string()
                .contains("invalid aggregate signature length")
        );
    }

    #[tokio::test]
    async fn verify_aggregate_rejects_invalid_signature_bytes() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let bad_sig = [0u8; BLS_SIGNATURE_BYTES];
        assert!(
            BlsSignature::sig_validate(&bad_sig, true).is_err(),
            "expected test signature bytes to be invalid"
        );
        let insts = Insts {
            ops: vec![Inst::Call {
                gas_limit: 0,
                contract: ContractAddress {
                    name: String::new(),
                    height: 0,
                    tx_index: 0,
                },
                nonce: Some(0),
                expr: String::new(),
            }],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![0],
                signature: bad_sig.to_vec(),
            }),
        };
        let err = verify_aggregate(&mut runtime, &insts)
            .await
            .expect_err("invalid signature bytes must be rejected");
        assert!(
            err.to_string()
                .contains("invalid aggregate signature bytes")
        );
    }

    #[tokio::test]
    async fn verify_aggregate_enforces_op_count_cap() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let ops: Vec<Inst> = (0..=MAX_BLS_BULK_OPS)
            .map(|_| Inst::Call {
                gas_limit: 0,
                contract: ContractAddress {
                    name: String::new(),
                    height: 0,
                    tx_index: 0,
                },
                nonce: Some(0),
                expr: String::new(),
            })
            .collect();
        let signer_ids: Vec<u64> = vec![0; ops.len()];
        let insts = Insts {
            ops,
            aggregate: Some(AggregateInfo {
                signer_ids,
                signature: vec![],
            }),
        };
        let err = verify_aggregate(&mut runtime, &insts)
            .await
            .expect_err("bundle op cap must be enforced");
        assert!(err.to_string().contains("max"));
    }

    #[tokio::test]
    async fn verify_aggregate_enforces_total_message_bytes_cap() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let expr = "a".repeat(MAX_BLS_BULK_TOTAL_MESSAGE_BYTES + 1024);
        let insts = Insts {
            ops: vec![Inst::Call {
                gas_limit: 0,
                contract: ContractAddress {
                    name: String::new(),
                    height: 0,
                    tx_index: 0,
                },
                nonce: Some(0),
                expr,
            }],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![0],
                signature: BlsSecretKey::key_gen(&[7u8; 32], &[])
                    .expect("BLS key_gen")
                    .sign(b"cap-test", KONTOR_BLS_DST, &[])
                    .to_bytes()
                    .to_vec(),
            }),
        };
        let err = verify_aggregate(&mut runtime, &insts)
            .await
            .expect_err("message bytes cap must be enforced");
        assert!(err.to_string().contains("signed message bytes exceed max"));
    }

    #[tokio::test]
    async fn verify_aggregate_rejects_register_bls_key() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let insts = Insts {
            ops: vec![Inst::RegisterBlsKey {
                bls_pubkey: vec![0u8; 96],
                schnorr_sig: vec![0u8; 64],
                bls_sig: vec![0u8; 48],
            }],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![0],
                signature: vec![0u8; 48],
            }),
        };
        let err = verify_aggregate(&mut runtime, &insts)
            .await
            .expect_err("RegisterBlsKey must be rejected in aggregate");
        assert!(
            err.to_string()
                .contains("RegisterBlsKey is not allowed in aggregate")
        );
    }

    #[tokio::test]
    async fn verify_aggregate_rejects_call_without_nonce() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let insts = Insts {
            ops: vec![Inst::Call {
                gas_limit: 0,
                contract: ContractAddress {
                    name: String::new(),
                    height: 0,
                    tx_index: 0,
                },
                nonce: None,
                expr: String::new(),
            }],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![0],
                signature: vec![0u8; 48],
            }),
        };
        let err = verify_aggregate(&mut runtime, &insts)
            .await
            .expect_err("aggregate Call without nonce must be rejected");
        assert!(err.to_string().contains("missing nonce"));
    }

    #[tokio::test]
    async fn verify_aggregate_rejects_publish() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let insts = Insts {
            ops: vec![Inst::Publish {
                gas_limit: 0,
                name: String::new(),
                bytes: vec![],
            }],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![0],
                signature: vec![0u8; 48],
            }),
        };
        let err = verify_aggregate(&mut runtime, &insts)
            .await
            .expect_err("aggregate Publish must be rejected");
        assert!(err.to_string().contains("got Publish"));
    }

    #[tokio::test]
    async fn verify_aggregate_rejects_issuance() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let insts = Insts {
            ops: vec![Inst::Issuance],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![0],
                signature: vec![0u8; 48],
            }),
        };
        let err = verify_aggregate(&mut runtime, &insts)
            .await
            .expect_err("aggregate Issuance must be rejected");
        assert!(err.to_string().contains("got Issuance"));
    }

    // -----------------------------------------------------------------------
    // SignerResolver unit tests
    // -----------------------------------------------------------------------

    #[allow(dead_code)]
    fn valid_bls_pubkey(ikm: &[u8; 32]) -> Vec<u8> {
        let sk = BlsSecretKey::key_gen(ikm, &[]).unwrap();
        sk.sk_to_pk().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn resolver_errors_on_unknown_signer_id() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let mut resolver = SignerResolver::new();
        resolver
            .resolve(&mut runtime, 999_999)
            .await
            .expect_err("unknown signer_id must be rejected");
        assert!(resolver.pk_cache.is_empty());
    }
}
