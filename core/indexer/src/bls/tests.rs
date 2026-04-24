use super::aggregate::SignerResolver;
use super::*;
use crate::database::connection::new_connection;
use crate::runtime::{ComponentCache, Runtime, Storage};
use bitcoin::key::rand;
use bitcoin::key::rand::RngCore;
use bitcoin::key::{Keypair, Secp256k1};
use blst::min_sig::{SecretKey as BlsSecretKey, Signature as BlsSignature};
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

/// Generate Example 1 from BLS_key_derivation_and_registration.md. Keeps
/// the test vectors in sync with the derivation code: run with
/// `-- --nocapture` to emit the values to paste back into the doc.
/// `bls_pubkey` and `bls_sig` are deterministic; `schnorr_sig` is not
/// (BIP-340 uses random aux_rand) so the doc treats it as illustrative.
#[test]
fn example_1_registration_proof_from_fixed_seed() {
    let seed_hex = "000102030405060708090a0b0c0d0e0f\
                    101112131415161718191a1b1c1d1e1f\
                    202122232425262728292a2b2c2d2e2f\
                    303132333435363738393a3b3c3d3e3f";
    let seed = hex::decode(seed_hex).expect("valid hex seed");

    // Regtest/testnet paths (coin_type=1) — Example 1's network.
    let keypair = crate::reg_tester::derive_taproot_keypair_from_seed(&seed, "m/86'/1'/0'/0/0")
        .expect("taproot derivation");
    let bls_sk = derivation::derive_bls_secret_key_eip2333(&seed, &[12381, 1, 0, 0])
        .expect("bls derivation");

    let proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes()).expect("registration proof");
    proof.verify().expect("proof verifies");

    let x_only_pubkey = hex::encode(proof.x_only_pubkey);
    let bls_pubkey = hex::encode(proof.bls_pubkey);
    let schnorr_sig = hex::encode(proof.schnorr_sig);
    let bls_sig = hex::encode(proof.bls_sig);
    println!("x_only_pubkey: {x_only_pubkey}");
    println!("bls_pubkey:    {bls_pubkey}");
    println!("schnorr_sig:   {schnorr_sig}  (non-deterministic)");
    println!("bls_sig:       {bls_sig}");

    // Sanity-check against the doc's published x_only_pubkey so the
    // Taproot derivation stays pinned. bls_pubkey / bls_sig are
    // deterministic from the seed too; see the doc.
    assert_eq!(
        x_only_pubkey,
        "a4b70d13d6d48919c40a0c0ddac146b18ba1dde08bd1af2224060040c6189282"
    );
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
            signature: vec![0u8; BLS_SIGNATURE_BYTES - 1],
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
    let insts = Insts {
        ops,
        aggregate: Some(AggregateInfo {
            signer_ids: vec![0; MAX_BLS_BULK_OPS + 1],
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

/*
RegisterBlsKey-specific aggregate/resolver tests are temporarily disabled.
We expect to revisit this area when inline registration is introduced.

#[tokio::test]
async fn verify_bls_bulk_rejects_invalid_register_pubkey_bytes() {
    let (mut runtime, _tmp) = new_test_runtime().await;
    let bad_pubkey = vec![0u8; 96];
    assert!(
        BlsPublicKey::key_validate(bad_pubkey.as_slice()).is_err(),
        "expected test pubkey bytes to be invalid"
    );
    let ops = vec![BlsBulkOp::RegisterBlsKey {
        signer: Signer::XOnlyPubKey("00".repeat(32)),
        bls_pubkey: bad_pubkey,
        schnorr_sig: vec![0u8; 64],
        bls_sig: vec![0u8; 48],
    }];

    let sk = BlsSecretKey::key_gen(&[9u8; 32], &[]).expect("BLS key_gen");
    let sig = sk.sign(b"bad-pk-test", KONTOR_BLS_DST, &[]).to_bytes();
    let err = verify_bls_bulk(&mut runtime, &ops, &sig)
        .await
        .expect_err("invalid pubkey bytes must be rejected");
    assert!(err.to_string().contains("invalid BLS pubkey"));
}

#[tokio::test]
async fn verify_bls_bulk_rejects_wrong_length_register_pubkey() {
    let (mut runtime, _tmp) = new_test_runtime().await;
    let sk = BlsSecretKey::key_gen(&[11u8; 32], &[]).expect("BLS key_gen");
    let sig_bytes = sk.sign(b"len-test", KONTOR_BLS_DST, &[]).to_bytes();

    for (label, bad_pubkey) in [
        ("too short (48 bytes)", vec![0xABu8; 48]),
        ("too long (128 bytes)", vec![0xCDu8; 128]),
        ("empty", vec![]),
    ] {
        let ops = vec![BlsBulkOp::RegisterBlsKey {
            signer: Signer::XOnlyPubKey("aa".repeat(32)),
            bls_pubkey: bad_pubkey,
            schnorr_sig: vec![0u8; 64],
            bls_sig: vec![0u8; 48],
        }];
        let err = verify_bls_bulk(&mut runtime, &ops, &sig_bytes)
            .await
            .expect_err(&format!("{label}: wrong-length pubkey must be rejected"));
        assert!(
            err.to_string().contains("invalid BLS pubkey"),
            "{label}: expected 'invalid BLS pubkey', got: {err}"
        );
    }
}

// -----------------------------------------------------------------------
// SignerResolver unit tests
// -----------------------------------------------------------------------

fn make_call_op(signer_id: u64) -> BlsBulkOp {
    BlsBulkOp::Call {
        signer_id,
        nonce: 0,
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "test".into(),
            height: 1,
            tx_index: 0,
        },
        expr: String::new(),
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
    let op = make_register_op(pubkey_bytes.clone());

    let mut resolver = SignerResolver::new();
    let pk = resolver.resolve(&mut runtime, &op).await.unwrap();

    let expected = BlsPublicKey::key_validate(&pubkey_bytes).unwrap();
    assert_eq!(pk.to_bytes(), expected.to_bytes());
}

#[tokio::test]
async fn resolver_caches_register_pubkey() {
    let (mut runtime, _tmp) = new_test_runtime().await;
    let pubkey_bytes = valid_bls_pubkey(&[2u8; 32]);
    let op = make_register_op(pubkey_bytes);

    let mut resolver = SignerResolver::new();
    let first = resolver.resolve(&mut runtime, &op).await.unwrap();
    let second = resolver.resolve(&mut runtime, &op).await.unwrap();

    assert_eq!(first.to_bytes(), second.to_bytes());
    assert_eq!(resolver.pk_cache.len(), 1);
}

#[tokio::test]
async fn resolver_distinguishes_different_register_pubkeys() {
    let (mut runtime, _tmp) = new_test_runtime().await;
    let op_a = make_register_op(valid_bls_pubkey(&[3u8; 32]));
    let op_b = make_register_op(valid_bls_pubkey(&[4u8; 32]));

    let mut resolver = SignerResolver::new();
    let pk_a = resolver.resolve(&mut runtime, &op_a).await.unwrap();
    let pk_b = resolver.resolve(&mut runtime, &op_b).await.unwrap();

    assert_ne!(pk_a.to_bytes(), pk_b.to_bytes());
    assert_eq!(resolver.pk_cache.len(), 2);
}

#[tokio::test]
async fn resolver_rejects_invalid_register_pubkey() {
    let (mut runtime, _tmp) = new_test_runtime().await;
    let op = make_register_op(vec![0u8; 96]);

    let mut resolver = SignerResolver::new();
    let err = resolver
        .resolve(&mut runtime, &op)
        .await
        .expect_err("invalid pubkey must be rejected");
    assert!(err.to_string().contains("invalid BLS pubkey"));
    assert!(resolver.pk_cache.is_empty());
}
*/

#[tokio::test]
async fn resolver_errors_on_unresolvable_call_and_does_not_cache() {
    let (mut runtime, _tmp) = new_test_runtime().await;
    let mut resolver = SignerResolver::new();
    resolver
        .resolve(&mut runtime, 999_999)
        .await
        .expect_err("unresolvable signer_id must be rejected");
    assert!(resolver.pk_cache.is_empty());
}

#[test]
fn rogue_key_forgery_succeeds_with_same_message() {
    use crate::test_utils::bls_test::{construct_rogue_g2_pubkey, derive_test_key};
    use blst::BLST_ERROR;

    let victim_sk = derive_test_key(10);
    let victim_pk = victim_sk.sk_to_pk();
    let beta_sk = derive_test_key(11);
    let beta_pk = beta_sk.sk_to_pk();
    let rogue_pk_bytes = construct_rogue_g2_pubkey(&beta_pk.to_bytes(), &victim_pk.to_bytes());
    let rogue_pk =
        blst::min_sig::PublicKey::key_validate(&rogue_pk_bytes).expect("rogue key must be valid");
    let msg = b"identical-message";
    let forged_sig = beta_sk.sign(msg, KONTOR_BLS_DST, &[]);
    let result = forged_sig.aggregate_verify(
        true,
        &[msg.as_slice(), msg.as_slice()],
        KONTOR_BLS_DST,
        &[&rogue_pk, &victim_pk],
        true,
    );
    assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
}

#[test]
fn rogue_key_forgery_fails_with_distinct_messages() {
    use crate::test_utils::bls_test::{construct_rogue_g2_pubkey, derive_test_key};
    use blst::BLST_ERROR;
    use blst::min_sig::AggregateSignature;

    let victim_sk = derive_test_key(10);
    let victim_pk = victim_sk.sk_to_pk();
    let beta_sk = derive_test_key(11);
    let beta_pk = beta_sk.sk_to_pk();
    let rogue_pk_bytes = construct_rogue_g2_pubkey(&beta_pk.to_bytes(), &victim_pk.to_bytes());
    let rogue_pk =
        blst::min_sig::PublicKey::key_validate(&rogue_pk_bytes).expect("rogue key must be valid");
    let msg_attacker = b"attacker-op-data";
    let msg_victim = b"victim-op-data";
    let victim_sig = victim_sk.sign(msg_victim, KONTOR_BLS_DST, &[]);
    let attacker_sig = beta_sk.sign(msg_attacker, KONTOR_BLS_DST, &[]);
    let agg =
        AggregateSignature::aggregate(&[&attacker_sig, &victim_sig], true).expect("aggregate");
    let agg_sig = agg.to_signature();
    let result = agg_sig.aggregate_verify(
        true,
        &[msg_attacker.as_slice(), msg_victim.as_slice()],
        KONTOR_BLS_DST,
        &[&rogue_pk, &victim_pk],
        true,
    );
    assert_ne!(result, BLST_ERROR::BLST_SUCCESS);
}

#[test]
fn bls_attack_eve_registers_own_key_under_alice_identity_aggregate_rejected() {
    use crate::test_utils::bls_test::derive_test_key;
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::key::{Keypair, Secp256k1, rand};
    use bitcoin::secp256k1::Message;

    let secp = Secp256k1::new();
    let _alice_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let eve_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let alice_xonly = _alice_keypair.x_only_public_key().0;
    let eve_bls_sk = derive_test_key(42);
    let eve_bls_pk = eve_bls_sk.sk_to_pk();
    let schnorr_msg = {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(&eve_bls_pk.to_bytes());
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        Message::from_digest_slice(&digest).expect("32-byte digest")
    };
    let eve_schnorr_sig = secp.sign_schnorr(&schnorr_msg, &eve_keypair).serialize();
    let bls_binding_msg = {
        let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + 32);
        msg.extend_from_slice(BLS_BINDING_PREFIX);
        msg.extend_from_slice(&alice_xonly.serialize());
        msg
    };
    let eve_bls_binding_sig = eve_bls_sk
        .sign(&bls_binding_msg, KONTOR_BLS_DST, &[])
        .to_bytes();
    let op = Inst::RegisterBlsKey {
        bls_pubkey: eve_bls_pk.to_bytes().to_vec(),
        schnorr_sig: eve_schnorr_sig.to_vec(),
        bls_sig: eve_bls_binding_sig.to_vec(),
    };
    let insts = Insts {
        ops: vec![op],
        aggregate: Some(AggregateInfo {
            signer_ids: vec![0],
            signature: vec![0u8; 48],
        }),
    };
    let err =
        validate_aggregate_shape(&insts).expect_err("aggregate RegisterBlsKey must be rejected");
    assert!(
        err.to_string()
            .contains("RegisterBlsKey is not allowed in aggregate")
    );
}

fn call_op(nonce: u64, gas_limit: u64, contract: ContractAddress, expr: impl Into<String>) -> Inst {
    Inst::Call {
        gas_limit,
        contract,
        nonce: Some(nonce),
        expr: expr.into(),
    }
}

#[test]
fn bls_bulk_aggregate_signature_roundtrip() {
    use crate::test_utils::bls_test::derive_test_key;
    use blst::BLST_ERROR;
    let sk1 = derive_test_key(1);
    let sk2 = derive_test_key(2);
    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();
    let contract = ContractAddress {
        name: "arith".into(),
        height: 123,
        tx_index: 4,
    };
    let op1 = call_op(0, 50_000, contract.clone(), "eval(10, id)");
    let op2 = call_op(0, 50_000, contract, "eval(10, sum({y: 8}))");
    let msg1 = op1.aggregate_signing_message(1).unwrap();
    let msg2 = op2.aggregate_signing_message(2).unwrap();
    let sig1 = sk1.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk2.sign(&msg2, KONTOR_BLS_DST, &[]);
    let agg = blst::min_sig::AggregateSignature::aggregate(&[&sig1, &sig2], true).unwrap();
    let msgs = [msg1, msg2];
    let refs: Vec<&[u8]> = msgs.iter().map(Vec::as_slice).collect();
    assert_eq!(
        agg.to_signature()
            .aggregate_verify(true, &refs, KONTOR_BLS_DST, &[&pk1, &pk2], true),
        BLST_ERROR::BLST_SUCCESS
    );
}

#[test]
fn bls_bulk_aggregate_signature_fails_if_op_bytes_change() {
    use crate::test_utils::bls_test::derive_test_key;
    use blst::BLST_ERROR;
    let sk1 = derive_test_key(7);
    let sk2 = derive_test_key(9);
    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();
    let contract = ContractAddress {
        name: "arith".into(),
        height: 123,
        tx_index: 4,
    };
    let msg1 = call_op(0, 50_000, contract.clone(), "eval(10, id)")
        .aggregate_signing_message(1)
        .unwrap();
    let msg2 = call_op(0, 50_000, contract, "eval(10, sum({y: 8}))")
        .aggregate_signing_message(2)
        .unwrap();
    let sig1 = sk1.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk2.sign(&msg2, KONTOR_BLS_DST, &[]);
    let agg = blst::min_sig::AggregateSignature::aggregate(&[&sig1, &sig2], true).unwrap();
    let msg1_mutated = call_op(
        0,
        60_000,
        ContractAddress {
            name: "arith".into(),
            height: 123,
            tx_index: 4,
        },
        "eval(10, id)",
    )
    .aggregate_signing_message(1)
    .unwrap();
    let msgs = [msg1_mutated, msg2];
    let refs: Vec<&[u8]> = msgs.iter().map(Vec::as_slice).collect();
    assert_ne!(
        agg.to_signature()
            .aggregate_verify(true, &refs, KONTOR_BLS_DST, &[&pk1, &pk2], true),
        BLST_ERROR::BLST_SUCCESS
    );
}

#[test]
fn bls_bulk_call_roundtrip_serialization_preserves_signer_id() {
    let op = call_op(
        7,
        50_000,
        ContractAddress {
            name: "arith".into(),
            height: 7,
            tx_index: 3,
        },
        "eval(10, id)",
    );
    let bytes = indexer_types::serialize(&(42u64, op.clone())).unwrap();
    let decoded: (u64, Inst) = indexer_types::deserialize(&bytes).unwrap();
    assert_eq!(decoded, (42, op));
}

#[test]
fn bls_bulk_message_changes_when_signer_id_changes() {
    let c = ContractAddress {
        name: "arith".into(),
        height: 123,
        tx_index: 4,
    };
    assert_ne!(
        call_op(0, 50_000, c.clone(), "eval(10, id)")
            .aggregate_signing_message(1)
            .unwrap(),
        call_op(0, 50_000, c, "eval(10, id)")
            .aggregate_signing_message(2)
            .unwrap()
    );
}

#[test]
fn bls_bulk_message_changes_when_nonce_changes() {
    let c = ContractAddress {
        name: "arith".into(),
        height: 123,
        tx_index: 4,
    };
    assert_ne!(
        call_op(0, 50_000, c.clone(), "eval(10, id)")
            .aggregate_signing_message(1)
            .unwrap(),
        call_op(1, 50_000, c, "eval(10, id)")
            .aggregate_signing_message(1)
            .unwrap()
    );
}

#[test]
fn bls_bulk_message_changes_when_gas_limit_changes() {
    let c = ContractAddress {
        name: "arith".into(),
        height: 123,
        tx_index: 4,
    };
    assert_ne!(
        call_op(0, 50_000, c.clone(), "eval(10, id)")
            .aggregate_signing_message(1)
            .unwrap(),
        call_op(0, 60_000, c, "eval(10, id)")
            .aggregate_signing_message(1)
            .unwrap()
    );
}

#[test]
fn bls_bulk_message_changes_when_contract_name_changes() {
    assert_ne!(
        call_op(
            0,
            50_000,
            ContractAddress {
                name: "token".into(),
                height: 1,
                tx_index: 0
            },
            "transfer(\"x\", 10)"
        )
        .aggregate_signing_message(1)
        .unwrap(),
        call_op(
            0,
            50_000,
            ContractAddress {
                name: "pool".into(),
                height: 1,
                tx_index: 0
            },
            "transfer(\"x\", 10)"
        )
        .aggregate_signing_message(1)
        .unwrap()
    );
}

#[test]
fn bls_bulk_message_changes_when_contract_height_changes() {
    assert_ne!(
        call_op(
            0,
            50_000,
            ContractAddress {
                name: "token".into(),
                height: 1,
                tx_index: 0
            },
            "transfer(\"x\", 10)"
        )
        .aggregate_signing_message(1)
        .unwrap(),
        call_op(
            0,
            50_000,
            ContractAddress {
                name: "token".into(),
                height: 2,
                tx_index: 0
            },
            "transfer(\"x\", 10)"
        )
        .aggregate_signing_message(1)
        .unwrap()
    );
}

#[test]
fn bls_bulk_message_changes_when_contract_tx_index_changes() {
    assert_ne!(
        call_op(
            0,
            50_000,
            ContractAddress {
                name: "token".into(),
                height: 1,
                tx_index: 0
            },
            "transfer(\"x\", 10)"
        )
        .aggregate_signing_message(1)
        .unwrap(),
        call_op(
            0,
            50_000,
            ContractAddress {
                name: "token".into(),
                height: 1,
                tx_index: 1
            },
            "transfer(\"x\", 10)"
        )
        .aggregate_signing_message(1)
        .unwrap()
    );
}

#[test]
fn bls_bulk_message_changes_when_expr_changes() {
    let c = ContractAddress {
        name: "token".into(),
        height: 1,
        tx_index: 0,
    };
    assert_ne!(
        call_op(0, 50_000, c.clone(), "transfer(\"alice\", 10)")
            .aggregate_signing_message(1)
            .unwrap(),
        call_op(0, 50_000, c, "transfer(\"bob\", 10)")
            .aggregate_signing_message(1)
            .unwrap()
    );
}

#[test]
fn bls_bulk_wrong_signer_key_fails_single_op() {
    use crate::test_utils::bls_test::derive_test_key;
    use blst::BLST_ERROR;
    let sk_a = derive_test_key(20);
    let sk_b = derive_test_key(21);
    let pk_a = sk_a.sk_to_pk();
    let msg = call_op(
        0,
        50_000,
        ContractAddress {
            name: "token".into(),
            height: 1,
            tx_index: 0,
        },
        "transfer(\"dest\", 100)",
    )
    .aggregate_signing_message(1)
    .unwrap();
    let sig_by_b = sk_b.sign(&msg, KONTOR_BLS_DST, &[]);
    assert_ne!(
        sig_by_b.aggregate_verify(true, &[msg.as_slice()], KONTOR_BLS_DST, &[&pk_a], true),
        BLST_ERROR::BLST_SUCCESS
    );
}

#[test]
fn bls_bulk_wrong_signer_key_fails_multi_op_key_swap() {
    use crate::test_utils::bls_test::derive_test_key;
    use blst::BLST_ERROR;
    let sk_a = derive_test_key(30);
    let sk_b = derive_test_key(31);
    let pk_a = sk_a.sk_to_pk();
    let pk_b = sk_b.sk_to_pk();
    let c = ContractAddress {
        name: "token".into(),
        height: 1,
        tx_index: 0,
    };
    let msg_a = call_op(0, 50_000, c.clone(), "transfer(\"x\", 10)")
        .aggregate_signing_message(1)
        .unwrap();
    let msg_b = call_op(0, 50_000, c, "transfer(\"y\", 20)")
        .aggregate_signing_message(2)
        .unwrap();
    let agg = blst::min_sig::AggregateSignature::aggregate(
        &[
            &sk_b.sign(&msg_a, KONTOR_BLS_DST, &[]),
            &sk_a.sign(&msg_b, KONTOR_BLS_DST, &[]),
        ],
        true,
    )
    .unwrap();
    assert_ne!(
        agg.to_signature().aggregate_verify(
            true,
            &[msg_a.as_slice(), msg_b.as_slice()],
            KONTOR_BLS_DST,
            &[&pk_a, &pk_b],
            true
        ),
        BLST_ERROR::BLST_SUCCESS
    );
}

#[test]
fn bls_bulk_one_correct_one_wrong_key_fails_entire_aggregate() {
    use crate::test_utils::bls_test::derive_test_key;
    use blst::BLST_ERROR;
    let sk_a = derive_test_key(40);
    let sk_b = derive_test_key(41);
    let sk_c = derive_test_key(42);
    let pk_a = sk_a.sk_to_pk();
    let pk_b = sk_b.sk_to_pk();
    let c = ContractAddress {
        name: "token".into(),
        height: 1,
        tx_index: 0,
    };
    let msg_a = call_op(0, 50_000, c.clone(), "transfer(\"x\", 10)")
        .aggregate_signing_message(1)
        .unwrap();
    let msg_b = call_op(0, 50_000, c, "transfer(\"y\", 20)")
        .aggregate_signing_message(2)
        .unwrap();
    let agg = blst::min_sig::AggregateSignature::aggregate(
        &[
            &sk_a.sign(&msg_a, KONTOR_BLS_DST, &[]),
            &sk_c.sign(&msg_b, KONTOR_BLS_DST, &[]),
        ],
        true,
    )
    .unwrap();
    assert_ne!(
        agg.to_signature().aggregate_verify(
            true,
            &[msg_a.as_slice(), msg_b.as_slice()],
            KONTOR_BLS_DST,
            &[&pk_a, &pk_b],
            true
        ),
        BLST_ERROR::BLST_SUCCESS
    );
}

mod proptest_bulk {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn signing_message_no_panic_on_arbitrary_call(
            signer_id in any::<u64>(),
            nonce in any::<u64>(),
            gas_limit in any::<u64>(),
            name in any::<String>(),
            height in any::<u64>(),
            tx_index in any::<u64>(),
            expr in any::<String>(),
        ) {
            let op = call_op(nonce, gas_limit, ContractAddress { name, height, tx_index }, expr);
            let msg = op.aggregate_signing_message(signer_id).expect("must not fail");
            prop_assert!(!msg.is_empty());
        }

        #[test]
        fn signing_message_no_panic_on_arbitrary_register(
            signer_id in any::<u64>(),
            bls_pubkey in proptest::collection::vec(any::<u8>(), 0..256),
            schnorr_sig in proptest::collection::vec(any::<u8>(), 0..256),
            bls_sig in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let op = Inst::RegisterBlsKey { bls_pubkey, schnorr_sig, bls_sig };
            let msg = op.aggregate_signing_message(signer_id).expect("must not fail");
            prop_assert!(!msg.is_empty());
        }
    }
}
