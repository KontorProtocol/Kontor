//! BLS12-381 signature verification and registration proofs for the Kontor protocol.
//!
//! Two registration paths share the same cryptographic binding semantics:
//! - **Direct** (`Inst::RegisterBlsKey`): [`DirectRegistrationProof`] carries both signatures.
//! - **Inline** (`BlsBulkOp::RegisterBlsKey`): the BLS PoP is folded into the aggregate;
//!   only the Schnorr binding travels as a field.
//!
//! Both paths use the same PoP message format: `KONTOR-POP-V1 || bls_pubkey || xonly_pubkey`.

use anyhow::{Result, anyhow};
use bitcoin::Network;
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::Message;
use blst::min_sig::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
};
use indexer_types::BlsBulkOp;
use indexer_types::Signer;
use std::collections::HashMap;
use std::str::FromStr;

use crate::runtime::Runtime;
use crate::runtime::registry::api::get_entry_by_id;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Domain-separating prefix for the Schnorr binding proof (Taproot → BLS).
pub const SCHNORR_BINDING_PREFIX: &[u8] = b"KONTOR_XONLY_TO_BLS_V1";

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
///   handled explicitly via [`DirectRegistrationProof`], which serves as the PoP. Using
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
/// Domain-separating prefix for BLS operation signing messages.
pub const KONTOR_OP_PREFIX: &[u8] = b"KONTOR-OP-V1";

/// Compressed BLS12-381 MinSig signature length in bytes.
pub const BLS_SIGNATURE_BYTES: usize = 48;

/// Hard cap on number of operations per `Inst::BlsBulk`.
pub const MAX_BLS_BULK_OPS: usize = 10_000;

/// Hard cap on total signed message bytes per `Inst::BlsBulk`.
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
pub(crate) fn schnorr_binding_message(bls_pubkey: &[u8; 96]) -> Message {
    let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
    preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
    preimage.extend_from_slice(bls_pubkey);
    let digest = sha256::Hash::hash(&preimage).to_byte_array();
    Message::from_digest_slice(&digest).expect("sha256 digest is 32 bytes")
}

async fn resolve_op_bls_pubkey_index(
    runtime: &mut Runtime,
    op: &BlsBulkOp,
    pubkeys: &mut Vec<BlsPublicKey>,
    pubkey_index_by_signer_id: &mut HashMap<u64, usize>,
    pubkey_index_by_raw: &mut HashMap<Vec<u8>, usize>,
    resolved_signers: &mut HashMap<u64, String>,
) -> Result<usize> {
    enum CacheKey {
        SignerId(u64),
        RawPubkey(Vec<u8>),
    }

    let (cache_key, pubkey_bytes) = match op {
        BlsBulkOp::Call { signer_id, .. } => {
            let signer_id = *signer_id;
            if let Some(&idx) = pubkey_index_by_signer_id.get(&signer_id) {
                return Ok(idx);
            }
            let entry = get_entry_by_id(runtime, signer_id).await?;
            let entry = entry.ok_or_else(|| anyhow!("unknown signer_id {signer_id}"))?;
            resolved_signers.insert(signer_id, entry.x_only_pubkey);
            (CacheKey::SignerId(signer_id), entry.bls_pubkey)
        }
        BlsBulkOp::RegisterBlsKey { bls_pubkey, .. } => {
            if let Some(&idx) = pubkey_index_by_raw.get(bls_pubkey.as_slice()) {
                return Ok(idx);
            }
            (CacheKey::RawPubkey(bls_pubkey.clone()), bls_pubkey.clone())
        }
    };

    let pk = BlsPublicKey::key_validate(pubkey_bytes.as_slice())
        .map_err(|e| anyhow!("invalid BLS pubkey (subgroup check failed): {e:?}"))?;
    pubkeys.push(pk);
    let idx = pubkeys.len() - 1;

    match cache_key {
        CacheKey::SignerId(signer_id) => {
            pubkey_index_by_signer_id.insert(signer_id, idx);
        }
        CacheKey::RawPubkey(raw) => {
            pubkey_index_by_raw.insert(raw, idx);
        }
    }

    Ok(idx)
}

/// Resolved signer identities from BLS bulk verification, keyed by `signer_id`.
/// The reactor uses these to avoid redundant registry lookups during execution.
pub type ResolvedSigners = HashMap<u64, String>;

pub async fn verify_bls_bulk(
    runtime: &mut Runtime,
    ops: &[BlsBulkOp],
    signature: &[u8],
) -> Result<ResolvedSigners> {
    if ops.is_empty() {
        return Err(anyhow!("BlsBulk must contain at least one operation"));
    }
    if ops.len() > MAX_BLS_BULK_OPS {
        return Err(anyhow!(
            "BlsBulk contains {} operations (max {})",
            ops.len(),
            MAX_BLS_BULK_OPS
        ));
    }
    if signature.len() != BLS_SIGNATURE_BYTES {
        return Err(anyhow!(
            "invalid aggregate signature length: expected {BLS_SIGNATURE_BYTES}, got {}",
            signature.len()
        ));
    }

    let aggregate_sig = BlsSignature::sig_validate(signature, true)
        .map_err(|e| anyhow!("invalid aggregate signature bytes: {e:?}"))?;

    let mut total_message_bytes: usize = 0;
    let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(ops.len());
    let mut pk_indices: Vec<usize> = Vec::with_capacity(ops.len());
    let mut unique_pks: Vec<BlsPublicKey> = Vec::new();
    let mut signer_pk_index: HashMap<u64, usize> = HashMap::new();
    let mut register_pk_index: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut resolved_signers: ResolvedSigners = HashMap::new();

    for op in ops.iter() {
        let msg = op.signing_message()?;

        total_message_bytes = total_message_bytes.saturating_add(msg.len());
        if total_message_bytes > MAX_BLS_BULK_TOTAL_MESSAGE_BYTES {
            return Err(anyhow!(
                "BlsBulk signed message bytes exceed max {}",
                MAX_BLS_BULK_TOTAL_MESSAGE_BYTES
            ));
        }
        msgs.push(msg);

        let pk_index = resolve_op_bls_pubkey_index(
            runtime,
            op,
            &mut unique_pks,
            &mut signer_pk_index,
            &mut register_pk_index,
            &mut resolved_signers,
        )
        .await?;
        pk_indices.push(pk_index);

        if let BlsBulkOp::RegisterBlsKey {
            signer, bls_pubkey, ..
        } = op
        {
            let Signer::XOnlyPubKey(xonly_hex) = signer else {
                return Err(anyhow!("RegisterBlsKey signer must be XOnlyPubKey"));
            };
            let xonly_pk = XOnlyPublicKey::from_str(xonly_hex)
                .map_err(|e| anyhow!("invalid x-only pubkey in RegisterBlsKey: {e}"))?;
            let pop_msg = BlsBulkOp::pop_message(bls_pubkey.as_slice(), &xonly_pk.serialize());
            total_message_bytes = total_message_bytes.saturating_add(pop_msg.len());
            if total_message_bytes > MAX_BLS_BULK_TOTAL_MESSAGE_BYTES {
                return Err(anyhow!(
                    "BlsBulk signed message bytes exceed max {}",
                    MAX_BLS_BULK_TOTAL_MESSAGE_BYTES
                ));
            }
            msgs.push(pop_msg);
            pk_indices.push(pk_index);
        }
    }

    let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let pk_refs: Vec<&BlsPublicKey> = pk_indices.iter().map(|i| &unique_pks[*i]).collect();
    let verify_result =
        aggregate_sig.aggregate_verify(true, msg_refs.as_slice(), KONTOR_BLS_DST, &pk_refs, true);
    if verify_result != blst::BLST_ERROR::BLST_SUCCESS {
        return Err(anyhow!(
            "BLS aggregate signature verification failed: {verify_result:?}"
        ));
    }

    Ok(resolved_signers)
}

// ---------------------------------------------------------------------------
// DirectRegistrationProof
// ---------------------------------------------------------------------------

/// Proof bundle for the **direct** registration path ([`Inst::RegisterBlsKey`]).
///
/// This type is specific to direct registration, where a user publishes their
/// own Bitcoin transaction and both binding proofs are verified independently.
/// The inline path ([`BlsBulkOp::RegisterBlsKey`]) does not use this type:
/// there, the BLS PoP is folded into the bundle's aggregate signature, and only
/// the Schnorr binding is verified separately.
///
/// Two signatures form a bidirectional binding:
/// - **Schnorr** (Taproot → BLS): Taproot key signs `sha256(SCHNORR_BINDING_PREFIX || bls_pubkey)`.
/// - **BLS PoP** (BLS → Taproot): BLS key signs `KONTOR-POP-V1 || bls_pubkey || xonly_pubkey`.
#[derive(Clone, Debug)]
pub struct DirectRegistrationProof {
    pub x_only_pubkey: [u8; 32],
    pub bls_pubkey: [u8; 96],
    pub schnorr_sig: [u8; 64],
    pub bls_sig: [u8; 48],
}

impl DirectRegistrationProof {
    /// Construct a registration proof by signing with both keys (wallet-side).
    pub fn new(keypair: &Keypair, bls_secret_key: &[u8; 32]) -> Result<Self> {
        let secp = Secp256k1::new();
        let x_only_pubkey = keypair.x_only_public_key().0.serialize();

        let bls_sk = BlsSecretKey::from_bytes(bls_secret_key)
            .map_err(|e| anyhow!("invalid BLS secret key: {e:?}"))?;
        let bls_pubkey = bls_sk.sk_to_pk().to_bytes();

        let schnorr_msg = schnorr_binding_message(&bls_pubkey);
        let schnorr_sig = secp.sign_schnorr(&schnorr_msg, keypair).serialize();

        let pop_msg = BlsBulkOp::pop_message(&bls_pubkey, &x_only_pubkey);
        let bls_sig = bls_sk.sign(&pop_msg, KONTOR_BLS_DST, &[]).to_bytes();

        Ok(Self {
            x_only_pubkey,
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        })
    }

    /// Verify both binding proofs using only the public data (indexer-side).
    pub fn verify(&self) -> Result<()> {
        let secp = Secp256k1::new();

        let schnorr_msg = schnorr_binding_message(&self.bls_pubkey);
        let x_only_pk = XOnlyPublicKey::from_slice(&self.x_only_pubkey)
            .map_err(|e| anyhow!("invalid x-only pubkey: {e}"))?;
        let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&self.schnorr_sig)
            .map_err(|e| anyhow!("invalid schnorr signature bytes: {e}"))?;
        secp.verify_schnorr(&schnorr_sig, &schnorr_msg, &x_only_pk)
            .map_err(|e| anyhow!("schnorr binding verification failed: {e}"))?;

        let bls_pk = BlsPublicKey::key_validate(&self.bls_pubkey)
            .map_err(|e| anyhow!("invalid BLS pubkey (subgroup check failed): {e:?}"))?;
        let bls_sig_obj = BlsSignature::sig_validate(&self.bls_sig, true)
            .map_err(|e| anyhow!("invalid BLS signature (subgroup check failed): {e:?}"))?;

        let pop_msg = BlsBulkOp::pop_message(&self.bls_pubkey, &self.x_only_pubkey);
        let result = bls_sig_obj.verify(true, &pop_msg, KONTOR_BLS_DST, &[], &bls_pk, true);
        if result != blst::BLST_ERROR::BLST_SUCCESS {
            return Err(anyhow!("BLS PoP verification failed: {result:?}"));
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
    use blst::min_sig::AggregateSignature;
    use indexer_types::{ContractAddress, Signer};
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

        let proof = DirectRegistrationProof::new(&keypair, &bls_sk.to_bytes()).unwrap();
        proof.verify().unwrap();
    }

    #[test]
    fn verify_rejects_wrong_schnorr_key() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());

        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        let bls_sk = BlsSecretKey::key_gen(&ikm, &[]).unwrap();

        let mut proof = DirectRegistrationProof::new(&keypair, &bls_sk.to_bytes()).unwrap();

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

        let mut proof = DirectRegistrationProof::new(&keypair, &bls_sk.to_bytes()).unwrap();

        // Swap in a different BLS pubkey — both verifications should fail.
        let mut ikm2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm2);
        let other_bls_sk = BlsSecretKey::key_gen(&ikm2, &[]).unwrap();
        proof.bls_pubkey = other_bls_sk.sk_to_pk().to_bytes();

        assert!(proof.verify().is_err());
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_empty_bundle() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let err = verify_bls_bulk(&mut runtime, &[], &[])
            .await
            .expect_err("empty bundle must be rejected");
        assert!(err.to_string().contains("at least one operation"));
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_wrong_signature_length() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let ops = vec![BlsBulkOp::Call {
            signer_id: 0,
            gas_limit: 0,
            contract: ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
            expr: String::new(),
        }];
        let short_sig = vec![0u8; BLS_SIGNATURE_BYTES - 1];
        let err = verify_bls_bulk(&mut runtime, &ops, &short_sig)
            .await
            .expect_err("wrong signature length must be rejected");
        assert!(
            err.to_string()
                .contains("invalid aggregate signature length")
        );
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_invalid_signature_bytes() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let ops = vec![BlsBulkOp::Call {
            signer_id: 0,
            gas_limit: 0,
            contract: ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
            expr: String::new(),
        }];
        let bad_sig = [0u8; BLS_SIGNATURE_BYTES];
        assert!(
            BlsSignature::sig_validate(&bad_sig, true).is_err(),
            "expected test signature bytes to be invalid"
        );
        let err = verify_bls_bulk(&mut runtime, &ops, &bad_sig)
            .await
            .expect_err("invalid signature bytes must be rejected");
        assert!(
            err.to_string()
                .contains("invalid aggregate signature bytes")
        );
    }

    #[tokio::test]
    async fn verify_bls_bulk_enforces_op_count_cap() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let mut ops: Vec<BlsBulkOp> = Vec::with_capacity(MAX_BLS_BULK_OPS + 1);
        for _ in 0..=MAX_BLS_BULK_OPS {
            ops.push(BlsBulkOp::Call {
                signer_id: 0,
                gas_limit: 0,
                contract: ContractAddress {
                    name: String::new(),
                    height: 0,
                    tx_index: 0,
                },
                expr: String::new(),
            });
        }
        let err = verify_bls_bulk(&mut runtime, &ops, &[])
            .await
            .expect_err("bundle op cap must be enforced");
        assert!(err.to_string().contains("max"));
    }

    #[tokio::test]
    async fn verify_bls_bulk_enforces_total_message_bytes_cap() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let expr = "a".repeat(MAX_BLS_BULK_TOTAL_MESSAGE_BYTES + 1024);
        let ops = vec![BlsBulkOp::Call {
            signer_id: 0,
            gas_limit: 0,
            contract: ContractAddress {
                name: String::new(),
                height: 0,
                tx_index: 0,
            },
            expr,
        }];

        let sk = BlsSecretKey::key_gen(&[7u8; 32], &[]).expect("BLS key_gen");
        let sig = sk.sign(b"cap-test", KONTOR_BLS_DST, &[]).to_bytes();
        let err = verify_bls_bulk(&mut runtime, &ops, &sig)
            .await
            .expect_err("message bytes cap must be enforced");
        assert!(err.to_string().contains("signed message bytes exceed max"));
    }

    fn test_xonly_hex() -> String {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        keypair.x_only_public_key().0.to_string()
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_invalid_register_pubkey_bytes() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let bad_pubkey = vec![0u8; 96];
        assert!(
            BlsPublicKey::key_validate(bad_pubkey.as_slice()).is_err(),
            "expected test pubkey bytes to be invalid"
        );
        let ops = vec![BlsBulkOp::RegisterBlsKey {
            signer: Signer::XOnlyPubKey(test_xonly_hex()),
            bls_pubkey: bad_pubkey,
            schnorr_sig: vec![0u8; 64],
        }];

        let sk = BlsSecretKey::key_gen(&[9u8; 32], &[]).expect("BLS key_gen");
        let sig = sk.sign(b"bad-pk-test", KONTOR_BLS_DST, &[]).to_bytes();
        let err = verify_bls_bulk(&mut runtime, &ops, &sig)
            .await
            .expect_err("invalid pubkey bytes must be rejected");
        assert!(err.to_string().contains("invalid BLS pubkey"));
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_register_op_missing_pop_signature() {
        let (mut runtime, _tmp) = new_test_runtime().await;

        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        let xonly = keypair.x_only_public_key().0;

        let sk = BlsSecretKey::key_gen(&[11u8; 32], &[]).expect("BLS key_gen");
        let pk_bytes = sk.sk_to_pk().to_bytes().to_vec();

        let op = BlsBulkOp::RegisterBlsKey {
            signer: Signer::XOnlyPubKey(xonly.to_string()),
            bls_pubkey: pk_bytes,
            schnorr_sig: vec![0u8; 64],
        };

        let msg = op.signing_message().expect("signing_message");
        let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]).to_bytes();

        let err = verify_bls_bulk(&mut runtime, &[op], &sig)
            .await
            .expect_err("missing PoP must reject bundle");
        assert!(
            err.to_string()
                .contains("BLS aggregate signature verification failed"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_register_op_with_wrong_pop_identity() {
        let (mut runtime, _tmp) = new_test_runtime().await;

        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        let xonly = keypair.x_only_public_key().0;
        let other_keypair = Keypair::new(&secp, &mut rand::thread_rng());
        let wrong_xonly = other_keypair.x_only_public_key().0;

        let sk = BlsSecretKey::key_gen(&[12u8; 32], &[]).expect("BLS key_gen");
        let pk_bytes = sk.sk_to_pk().to_bytes().to_vec();

        let op = BlsBulkOp::RegisterBlsKey {
            signer: Signer::XOnlyPubKey(xonly.to_string()),
            bls_pubkey: pk_bytes.clone(),
            schnorr_sig: vec![0u8; 64],
        };

        let msg = op.signing_message().expect("signing_message");
        let sig_op = sk.sign(&msg, KONTOR_BLS_DST, &[]);

        let wrong_pop_msg = BlsBulkOp::pop_message(pk_bytes.as_slice(), &wrong_xonly.serialize());
        let sig_pop_wrong = sk.sign(&wrong_pop_msg, KONTOR_BLS_DST, &[]);

        let aggregate =
            AggregateSignature::aggregate(&[&sig_op, &sig_pop_wrong], true).expect("aggregate");
        let agg_bytes = aggregate.to_signature().to_bytes().to_vec();

        let err = verify_bls_bulk(&mut runtime, &[op], agg_bytes.as_slice())
            .await
            .expect_err("wrong identity in PoP must reject bundle");
        assert!(
            err.to_string()
                .contains("BLS aggregate signature verification failed"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_register_op_if_op_signature_is_reused_as_pop() {
        let (mut runtime, _tmp) = new_test_runtime().await;

        let sk = BlsSecretKey::key_gen(&[13u8; 32], &[]).expect("BLS key_gen");
        let pk_bytes = sk.sk_to_pk().to_bytes().to_vec();

        let op = BlsBulkOp::RegisterBlsKey {
            signer: Signer::XOnlyPubKey(test_xonly_hex()),
            bls_pubkey: pk_bytes,
            schnorr_sig: vec![0u8; 64],
        };

        let msg = op.signing_message().expect("signing_message");
        let sig_op = sk.sign(&msg, KONTOR_BLS_DST, &[]);

        let aggregate =
            AggregateSignature::aggregate(&[&sig_op, &sig_op], true).expect("aggregate");
        let agg_bytes = aggregate.to_signature().to_bytes().to_vec();

        let err = verify_bls_bulk(&mut runtime, &[op], agg_bytes.as_slice())
            .await
            .expect_err("reusing op signature for PoP must reject bundle");
        assert!(
            err.to_string()
                .contains("BLS aggregate signature verification failed"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_non_xonly_signer_in_register() {
        let (mut runtime, _tmp) = new_test_runtime().await;

        let sk = BlsSecretKey::key_gen(&[15u8; 32], &[]).expect("BLS key_gen");
        let pk_bytes = sk.sk_to_pk().to_bytes().to_vec();

        let op = BlsBulkOp::RegisterBlsKey {
            signer: Signer::Nobody,
            bls_pubkey: pk_bytes,
            schnorr_sig: vec![0u8; 64],
        };

        let msg = op.signing_message().expect("signing_message");
        let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]).to_bytes();

        let err = verify_bls_bulk(&mut runtime, &[op], &sig)
            .await
            .expect_err("non-XOnlyPubKey signer must be rejected");
        assert!(
            err.to_string().contains("must be XOnlyPubKey"),
            "unexpected error: {err:?}"
        );
    }
}
