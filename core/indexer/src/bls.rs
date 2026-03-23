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
use indexer_types::{AggregateInst, Inst, InstructionEnvelope, SignerRef};
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

/// Hard cap on number of operations per aggregate instruction envelope.
pub const MAX_BLS_BULK_OPS: usize = 10_000;

/// Hard cap on total signed message bytes per aggregate instruction envelope.
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
// SignerResolver — deduplicated BLS pubkey resolution for bundle verification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SignerKey {
    RegistryId(u64),
    RawPubkey(Vec<u8>),
}

/// Resolved signer_id → x_only_pubkey mapping returned by [`verify_instruction_envelope`]
/// so the reactor can look up signers without redundant registry calls.
pub type SignerMap = HashMap<u64, String>;

struct SignerResolver {
    pk_cache: HashMap<SignerKey, BlsPublicKey>,
    signer_map: SignerMap,
}

impl SignerResolver {
    fn new() -> Self {
        Self {
            pk_cache: HashMap::new(),
            signer_map: HashMap::new(),
        }
    }

    async fn resolve(&mut self, runtime: &mut Runtime, op: &AggregateInst) -> Result<BlsPublicKey> {
        let key = match (&op.signer, &op.inst) {
            (SignerRef::SignerId { id }, _) => SignerKey::RegistryId(*id),
            (_, Inst::RegisterBlsKey { bls_pubkey, .. }) => {
                SignerKey::RawPubkey(bls_pubkey.clone())
            }
            _ => {
                return Err(anyhow!(
                    "aggregate signer must be a registry id unless registering a BLS key"
                ));
            }
        };

        if let Some(pk) = self.pk_cache.get(&key) {
            return Ok(*pk);
        }

        let raw_bytes = match (&op.signer, &op.inst) {
            (SignerRef::SignerId { id }, _) => {
                let entry = get_entry_by_id(runtime, *id).await?;
                let entry = entry.ok_or_else(|| anyhow!("unknown signer_id {id}"))?;
                self.signer_map.insert(*id, entry.x_only_pubkey.clone());
                entry
                    .bls_pubkey
                    .ok_or_else(|| anyhow!("signer_id {id} has no BLS pubkey registered"))?
            }
            (_, Inst::RegisterBlsKey { bls_pubkey, .. }) => bls_pubkey.clone(),
            _ => {
                return Err(anyhow!(
                    "aggregate signer must be a registry id unless registering a BLS key"
                ));
            }
        };

        let pk = BlsPublicKey::key_validate(&raw_bytes)
            .map_err(|e| anyhow!("invalid BLS pubkey (subgroup check failed): {e:?}"))?;
        self.pk_cache.insert(key, pk);
        Ok(pk)
    }
}

pub async fn verify_instruction_envelope(
    runtime: &mut Runtime,
    envelope: &InstructionEnvelope,
) -> Result<SignerMap> {
    let (ops, signature) = match envelope {
        InstructionEnvelope::Aggregate { ops, signature } => (ops.as_slice(), signature.as_slice()),
        InstructionEnvelope::Direct { .. } => {
            return Err(anyhow!(
                "verify_instruction_envelope requires an aggregate instruction envelope"
            ));
        }
    };
    // 1) Basic sanity: empty bundles are not meaningful and should be rejected.
    if ops.is_empty() {
        return Err(anyhow!(
            "aggregate instruction envelope must contain at least one operation"
        ));
    }
    // 2) DoS hardening: cap per-bundle work (pubkey lookups + hashing + pairing checks).
    if ops.len() > MAX_BLS_BULK_OPS {
        return Err(anyhow!(
            "aggregate instruction envelope contains {} operations (max {})",
            ops.len(),
            MAX_BLS_BULK_OPS
        ));
    }
    // 3) Quick reject: Kontor expects a single compressed MinSig signature (48 bytes).
    if signature.len() != BLS_SIGNATURE_BYTES {
        return Err(anyhow!(
            "invalid aggregate signature length: expected {BLS_SIGNATURE_BYTES}, got {}",
            signature.len()
        ));
    }

    // 4) Parse + validate signature (includes subgroup check) before spending effort
    // building messages and resolving pubkeys.
    let aggregate_sig = BlsSignature::sig_validate(signature, true)
        .map_err(|e| anyhow!("invalid aggregate signature bytes: {e:?}"))?;

    // 5) Build the two parallel vecs that aggregate_verify needs: one message and one
    // pubkey per op. The resolver deduplicates registry lookups and subgroup checks
    // across ops that share a signer.
    let mut resolver = SignerResolver::new();
    let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(ops.len());
    let mut pks: Vec<BlsPublicKey> = Vec::with_capacity(ops.len());
    let mut total_message_bytes: usize = 0;

    for op in ops {
        // Reconstruct the exact bytes each signer authorized. If the bundler
        // mutates any op field after signing, this message changes and verification fails.
        let msg = op.signing_message()?;
        total_message_bytes = total_message_bytes.saturating_add(msg.len());
        if total_message_bytes > MAX_BLS_BULK_TOTAL_MESSAGE_BYTES {
            return Err(anyhow!(
                "aggregate envelope signed message bytes exceed max {}",
                MAX_BLS_BULK_TOTAL_MESSAGE_BYTES
            ));
        }
        // Resolve the BLS pubkey for this op (registry lookup for Calls, inline for
        // RegisterBlsKey). Cached per unique signer to avoid redundant subgroup checks.
        pks.push(resolver.resolve(runtime, op).await?);
        msgs.push(msg);
    }

    // 6) Aggregate verify: proves every op's message was signed by the corresponding
    // signer, while only storing a single 48-byte signature on-chain.
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
    use indexer_types::ContractAddress;
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

    fn aggregate_call_op(signer_id: u64) -> AggregateInst {
        AggregateInst {
            signer: SignerRef::SignerId { id: signer_id },
            inst: Inst::Call {
                gas_limit: 50_000,
                contract: ContractAddress {
                    name: "test".into(),
                    height: 1,
                    tx_index: 0,
                },
                nonce: Some(0),
                expr: String::new(),
            },
        }
    }

    fn aggregate_register_op(bls_pubkey: Vec<u8>) -> AggregateInst {
        AggregateInst {
            signer: SignerRef::XOnlyPubKey("aa".repeat(32)),
            inst: Inst::RegisterBlsKey {
                bls_pubkey,
                schnorr_sig: vec![0u8; 64],
                bls_sig: vec![0u8; 48],
            },
        }
    }

    fn aggregate_envelope(ops: Vec<AggregateInst>, signature: Vec<u8>) -> InstructionEnvelope {
        InstructionEnvelope::Aggregate { ops, signature }
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_empty_bundle() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let err = verify_instruction_envelope(&mut runtime, &aggregate_envelope(vec![], vec![]))
            .await
            .expect_err("empty bundle must be rejected");
        assert!(err.to_string().contains("at least one operation"));
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_wrong_signature_length() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let short_sig = vec![0u8; BLS_SIGNATURE_BYTES - 1];
        let err = verify_instruction_envelope(
            &mut runtime,
            &aggregate_envelope(vec![aggregate_call_op(0)], short_sig),
        )
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
        let bad_sig = [0u8; BLS_SIGNATURE_BYTES];
        assert!(BlsSignature::sig_validate(&bad_sig, true).is_err());
        let err = verify_instruction_envelope(
            &mut runtime,
            &aggregate_envelope(vec![aggregate_call_op(0)], bad_sig.to_vec()),
        )
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
        let mut ops = Vec::with_capacity(MAX_BLS_BULK_OPS + 1);
        for _ in 0..=MAX_BLS_BULK_OPS {
            ops.push(aggregate_call_op(0));
        }
        let err = verify_instruction_envelope(&mut runtime, &aggregate_envelope(ops, vec![]))
            .await
            .expect_err("bundle op cap must be enforced");
        assert!(err.to_string().contains("max"));
    }

    #[tokio::test]
    async fn verify_bls_bulk_enforces_total_message_bytes_cap() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let expr = "a".repeat(MAX_BLS_BULK_TOTAL_MESSAGE_BYTES + 1024);
        let ops = vec![AggregateInst {
            signer: SignerRef::SignerId { id: 0 },
            inst: Inst::Call {
                gas_limit: 0,
                contract: ContractAddress {
                    name: String::new(),
                    height: 0,
                    tx_index: 0,
                },
                nonce: Some(0),
                expr,
            },
        }];

        let sk = BlsSecretKey::key_gen(&[7u8; 32], &[]).expect("BLS key_gen");
        let sig = sk.sign(b"cap-test", KONTOR_BLS_DST, &[]).to_bytes();
        let err = verify_instruction_envelope(&mut runtime, &aggregate_envelope(ops, sig.to_vec()))
            .await
            .expect_err("message bytes cap must be enforced");
        assert!(err.to_string().contains("signed message bytes exceed max"));
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_invalid_register_pubkey_bytes() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let bad_pubkey = vec![0u8; 96];
        assert!(BlsPublicKey::key_validate(bad_pubkey.as_slice()).is_err());
        let sk = BlsSecretKey::key_gen(&[9u8; 32], &[]).expect("BLS key_gen");
        let sig = sk.sign(b"bad-pk-test", KONTOR_BLS_DST, &[]).to_bytes();
        let err = verify_instruction_envelope(
            &mut runtime,
            &aggregate_envelope(vec![aggregate_register_op(bad_pubkey)], sig.to_vec()),
        )
        .await
        .expect_err("invalid pubkey bytes must be rejected");
        assert!(err.to_string().contains("invalid BLS pubkey"));
    }

    #[tokio::test]
    async fn verify_bls_bulk_rejects_wrong_length_register_pubkey() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let sk = BlsSecretKey::key_gen(&[11u8; 32], &[]).expect("BLS key_gen");
        let sig_bytes = sk
            .sign(b"len-test", KONTOR_BLS_DST, &[])
            .to_bytes()
            .to_vec();

        for (label, bad_pubkey) in [
            ("too short (48 bytes)", vec![0xABu8; 48]),
            ("too long (128 bytes)", vec![0xCDu8; 128]),
            ("empty", vec![]),
        ] {
            let err = verify_instruction_envelope(
                &mut runtime,
                &aggregate_envelope(vec![aggregate_register_op(bad_pubkey)], sig_bytes.clone()),
            )
            .await
            .expect_err(&format!("{label}: wrong-length pubkey must be rejected"));
            assert!(
                err.to_string().contains("invalid BLS pubkey"),
                "{label}: expected 'invalid BLS pubkey', got: {err}"
            );
        }
    }

    fn valid_bls_pubkey(ikm: &[u8; 32]) -> Vec<u8> {
        let sk = BlsSecretKey::key_gen(ikm, &[]).unwrap();
        sk.sk_to_pk().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn resolver_returns_valid_pubkey_for_register_op() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let pubkey_bytes = valid_bls_pubkey(&[1u8; 32]);
        let op = aggregate_register_op(pubkey_bytes.clone());

        let mut resolver = SignerResolver::new();
        let pk = resolver.resolve(&mut runtime, &op).await.unwrap();

        let expected = BlsPublicKey::key_validate(&pubkey_bytes).unwrap();
        assert_eq!(pk.to_bytes(), expected.to_bytes());
    }

    #[tokio::test]
    async fn resolver_caches_register_pubkey() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let pubkey_bytes = valid_bls_pubkey(&[2u8; 32]);
        let op = aggregate_register_op(pubkey_bytes);

        let mut resolver = SignerResolver::new();
        let first = resolver.resolve(&mut runtime, &op).await.unwrap();
        let second = resolver.resolve(&mut runtime, &op).await.unwrap();

        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(resolver.pk_cache.len(), 1);
    }

    #[tokio::test]
    async fn resolver_distinguishes_different_register_pubkeys() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let op_a = aggregate_register_op(valid_bls_pubkey(&[3u8; 32]));
        let op_b = aggregate_register_op(valid_bls_pubkey(&[4u8; 32]));

        let mut resolver = SignerResolver::new();
        let pk_a = resolver.resolve(&mut runtime, &op_a).await.unwrap();
        let pk_b = resolver.resolve(&mut runtime, &op_b).await.unwrap();

        assert_ne!(pk_a.to_bytes(), pk_b.to_bytes());
        assert_eq!(resolver.pk_cache.len(), 2);
    }

    #[tokio::test]
    async fn resolver_rejects_invalid_register_pubkey() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let op = aggregate_register_op(vec![0u8; 96]);

        let mut resolver = SignerResolver::new();
        let err = resolver
            .resolve(&mut runtime, &op)
            .await
            .expect_err("invalid pubkey must be rejected");
        assert!(err.to_string().contains("invalid BLS pubkey"));
        assert!(resolver.pk_cache.is_empty());
    }

    #[tokio::test]
    async fn resolver_errors_on_unresolvable_call_and_does_not_cache() {
        let (mut runtime, _tmp) = new_test_runtime().await;
        let op = aggregate_call_op(999_999);

        let mut resolver = SignerResolver::new();
        resolver
            .resolve(&mut runtime, &op)
            .await
            .expect_err("unresolvable signer_id must be rejected");
        assert!(resolver.pk_cache.is_empty());
    }
}
