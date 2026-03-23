use anyhow::Result;
use blst::min_sig::AggregateSignature;
use blst::min_sig::SecretKey as BlsSecretKey;
use indexer::bls::{KONTOR_BLS_DST, RegistrationProof};
use indexer_types::{AggregateInst, Inst, InstructionEnvelope, SignerRef};
use testlib::*;

import!(
    name = "registry",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
);

//TODO
fn aggregate_register_op(x_only: String, proof: &RegistrationProof) -> AggregateInst {
    AggregateInst {
        signer: SignerRef::XOnlyPubKey(x_only),
        inst: Inst::RegisterBlsKey {
            bls_pubkey: proof.bls_pubkey.to_vec(),
            schnorr_sig: proof.schnorr_sig.to_vec(),
            bls_sig: proof.bls_sig.to_vec(),
        },
    }
}

fn aggregate_envelope(ops: Vec<AggregateInst>, signature: Vec<u8>) -> InstructionEnvelope {
    InstructionEnvelope::Aggregate { ops, signature }
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_register_direct_regtest() -> Result<()> {
    let mut user = reg_tester.unregistered_identity().await?;

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    reg_tester
        .instruction(
            &mut user,
            Inst::RegisterBlsKey {
                bls_pubkey: proof.bls_pubkey.to_vec(),
                schnorr_sig: proof.schnorr_sig.to_vec(),
                bls_sig: proof.bls_sig.to_vec(),
            },
        )
        .await?;

    let xonly = user.x_only_public_key().to_string();
    let signer_id = registry::get_signer_id(runtime, &xonly).await?;
    assert_eq!(signer_id, Some(0));

    let registered_bls_pubkey = registry::get_bls_pubkey(runtime, &xonly).await?;
    assert_eq!(registered_bls_pubkey, Some(proof.bls_pubkey.to_vec()));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_register_in_bls_bulk_regtest() -> Result<()> {
    let user1 = reg_tester.unregistered_identity().await?;
    let user2 = reg_tester.unregistered_identity().await?;
    let mut publisher = reg_tester.unregistered_identity().await?;

    let proof1 = RegistrationProof::new(&user1.keypair, &user1.bls_secret_key)?;
    let proof2 = RegistrationProof::new(&user2.keypair, &user2.bls_secret_key)?;

    let op0 = aggregate_register_op(user1.x_only_public_key().to_string(), &proof1);
    let op1 = aggregate_register_op(user2.x_only_public_key().to_string(), &proof2);

    let msg0 = op0.signing_message()?;
    let msg1 = op1.signing_message()?;

    let sk1 = blst::min_sig::SecretKey::from_bytes(&user1.bls_secret_key).unwrap();
    let sk2 = blst::min_sig::SecretKey::from_bytes(&user2.bls_secret_key).unwrap();
    let sig0 = sk1.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk2.sign(&msg1, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1], true).unwrap();
    let aggregate_sig = aggregate.to_signature();

    let _res = reg_tester
        .instruction_envelope(
            &mut publisher,
            aggregate_envelope(vec![op0, op1], aggregate_sig.to_bytes().to_vec()),
        )
        .await?;

    // The Taproot envelope signer (publisher) is auto-registered by the indexer.
    let publisher_xonly = publisher.x_only_public_key().to_string();
    let publisher_id = registry::get_signer_id(runtime, &publisher_xonly)
        .await?
        .expect("publisher must have a signer_id");

    let xonly1 = user1.x_only_public_key().to_string();
    let xonly2 = user2.x_only_public_key().to_string();
    assert_eq!(
        registry::get_signer_id(runtime, &xonly1).await?,
        Some(publisher_id + 1)
    );
    assert_eq!(
        registry::get_signer_id(runtime, &xonly2).await?,
        Some(publisher_id + 2)
    );
    assert_eq!(
        registry::get_bls_pubkey(runtime, &xonly1).await?,
        Some(proof1.bls_pubkey.to_vec())
    );
    assert_eq!(
        registry::get_bls_pubkey(runtime, &xonly2).await?,
        Some(proof2.bls_pubkey.to_vec())
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_register_same_key_twice_is_idempotent_regtest() -> Result<()> {
    let mut user = reg_tester.unregistered_identity().await?;

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    reg_tester
        .instruction(
            &mut user,
            Inst::RegisterBlsKey {
                bls_pubkey: proof.bls_pubkey.to_vec(),
                schnorr_sig: proof.schnorr_sig.to_vec(),
                bls_sig: proof.bls_sig.to_vec(),
            },
        )
        .await?;

    let xonly = user.x_only_public_key().to_string();
    let signer_id_before = registry::get_signer_id(runtime, &xonly).await?;
    let pk_before = registry::get_bls_pubkey(runtime, &xonly).await?;

    // Second registration with same key hits the early-return optimization in
    // register_bls_key, so no contract result is recorded. Ignore the result-lookup error.
    let _ = reg_tester
        .instruction(
            &mut user,
            Inst::RegisterBlsKey {
                bls_pubkey: proof.bls_pubkey.to_vec(),
                schnorr_sig: proof.schnorr_sig.to_vec(),
                bls_sig: proof.bls_sig.to_vec(),
            },
        )
        .await;

    let signer_id_after = registry::get_signer_id(runtime, &xonly).await?;
    let pk_after = registry::get_bls_pubkey(runtime, &xonly).await?;

    assert_eq!(signer_id_before, signer_id_after);
    assert_eq!(pk_before, pk_after);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_rejects_different_key_for_same_signer_regtest() -> Result<()> {
    let mut user = reg_tester.unregistered_identity().await?;

    let original = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    reg_tester
        .instruction(
            &mut user,
            Inst::RegisterBlsKey {
                bls_pubkey: original.bls_pubkey.to_vec(),
                schnorr_sig: original.schnorr_sig.to_vec(),
                bls_sig: original.bls_sig.to_vec(),
            },
        )
        .await?;

    let mut ikm = [0u8; 32];
    ikm[0] = 99;
    let alt_sk = BlsSecretKey::key_gen(&ikm, &[]).expect("alt key_gen");
    let alt_proof = RegistrationProof::new(&user.keypair, &alt_sk.to_bytes())?;

    let xonly = user.x_only_public_key().to_string();
    let signer_id_before = registry::get_signer_id(runtime, &xonly).await?;
    let pk_before = registry::get_bls_pubkey(runtime, &xonly).await?;

    let _res = reg_tester
        .instruction(
            &mut user,
            Inst::RegisterBlsKey {
                bls_pubkey: alt_proof.bls_pubkey.to_vec(),
                schnorr_sig: alt_proof.schnorr_sig.to_vec(),
                bls_sig: alt_proof.bls_sig.to_vec(),
            },
        )
        .await?;

    let signer_id_after = registry::get_signer_id(runtime, &xonly).await?;
    let pk_after = registry::get_bls_pubkey(runtime, &xonly).await?;
    assert_eq!(signer_id_before, signer_id_after);
    assert_eq!(pk_before, pk_after);
    assert_eq!(pk_after, Some(original.bls_pubkey.to_vec()));
    Ok(())
}

/// Two `RegisterBlsKey` ops for the same x-only with the SAME BLS key in one
/// bundle. The first creates the registry entry; the second hits the
/// idempotent early-return. The result must be exactly one entry with one
/// signer ID, and a subsequent registration must get the next sequential ID
/// (no gap).
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_duplicate_same_key_in_bundle_idempotent_regtest() -> Result<()> {
    let user = reg_tester.unregistered_identity().await?;
    let mut publisher = reg_tester.unregistered_identity().await?;

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    let user_xonly = user.x_only_public_key().to_string();

    let op = aggregate_register_op(user_xonly.clone(), &proof);

    let msg = op.signing_message()?;
    let bls_sk = BlsSecretKey::from_bytes(&user.bls_secret_key).unwrap();
    let sig = bls_sk.sign(&msg, KONTOR_BLS_DST, &[]);
    let agg = AggregateSignature::aggregate(&[&sig, &sig], true).unwrap();

    let _ = reg_tester
        .instruction_envelope(
            &mut publisher,
            aggregate_envelope(vec![op.clone(), op], agg.to_signature().to_bytes().to_vec()),
        )
        .await;

    let publisher_xonly = publisher.x_only_public_key().to_string();
    let publisher_id = registry::get_signer_id(runtime, &publisher_xonly)
        .await?
        .expect("publisher must have a signer_id");

    let user_id = registry::get_signer_id(runtime, &user_xonly)
        .await?
        .expect("user must have a signer_id");
    assert_eq!(
        user_id,
        publisher_id + 1,
        "duplicate same-key register must produce exactly one entry"
    );
    assert_eq!(
        registry::get_bls_pubkey(runtime, &user_xonly).await?,
        Some(proof.bls_pubkey.to_vec()),
    );

    let mut next_user = reg_tester.unregistered_identity().await?;
    let next_proof = RegistrationProof::new(&next_user.keypair, &next_user.bls_secret_key)?;
    reg_tester
        .instruction(
            &mut next_user,
            Inst::RegisterBlsKey {
                bls_pubkey: next_proof.bls_pubkey.to_vec(),
                schnorr_sig: next_proof.schnorr_sig.to_vec(),
                bls_sig: next_proof.bls_sig.to_vec(),
            },
        )
        .await?;
    let next_xonly = next_user.x_only_public_key().to_string();
    let next_id = registry::get_signer_id(runtime, &next_xonly)
        .await?
        .expect("next user must have a signer_id");
    assert_eq!(
        next_id,
        user_id + 1,
        "next registration after idempotent duplicate must get sequential ID (no gap)"
    );

    Ok(())
}

/// Two `RegisterBlsKey` ops for the same x-only with DIFFERENT BLS keys in one
/// bundle. The first registration succeeds; the second is rejected by the
/// registry ("BLS pubkey already registered for signer"). The original key
/// must remain, and no ID gap is created.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_different_keys_same_xonly_in_bundle_first_wins_regtest() -> Result<()> {
    let user = reg_tester.unregistered_identity().await?;
    let mut publisher = reg_tester.unregistered_identity().await?;

    let proof_a = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;

    let mut alt_ikm = [0u8; 32];
    alt_ikm[0] = 0xBB;
    let alt_sk = BlsSecretKey::key_gen(&alt_ikm, &[]).expect("alt key_gen");
    let proof_b = RegistrationProof::new(&user.keypair, &alt_sk.to_bytes())?;

    let user_xonly = user.x_only_public_key().to_string();

    let op_a = aggregate_register_op(user_xonly.clone(), &proof_a);
    let op_b = aggregate_register_op(user_xonly.clone(), &proof_b);

    let msg_a = op_a.signing_message()?;
    let msg_b = op_b.signing_message()?;

    let sk_a = BlsSecretKey::from_bytes(&user.bls_secret_key).unwrap();
    let sig_a = sk_a.sign(&msg_a, KONTOR_BLS_DST, &[]);
    let sig_b = alt_sk.sign(&msg_b, KONTOR_BLS_DST, &[]);
    let agg = AggregateSignature::aggregate(&[&sig_a, &sig_b], true).unwrap();

    let _ = reg_tester
        .instruction_envelope(
            &mut publisher,
            aggregate_envelope(vec![op_a, op_b], agg.to_signature().to_bytes().to_vec()),
        )
        .await;

    let publisher_xonly = publisher.x_only_public_key().to_string();
    let publisher_id = registry::get_signer_id(runtime, &publisher_xonly)
        .await?
        .expect("publisher must have a signer_id");

    let user_id = registry::get_signer_id(runtime, &user_xonly)
        .await?
        .expect("user must have a signer_id");
    assert_eq!(user_id, publisher_id + 1, "first key must win registration");
    assert_eq!(
        registry::get_bls_pubkey(runtime, &user_xonly).await?,
        Some(proof_a.bls_pubkey.to_vec()),
        "original key must remain after conflicting second registration"
    );

    let mut next_user = reg_tester.unregistered_identity().await?;
    let next_proof = RegistrationProof::new(&next_user.keypair, &next_user.bls_secret_key)?;
    reg_tester
        .instruction(
            &mut next_user,
            Inst::RegisterBlsKey {
                bls_pubkey: next_proof.bls_pubkey.to_vec(),
                schnorr_sig: next_proof.schnorr_sig.to_vec(),
                bls_sig: next_proof.bls_sig.to_vec(),
            },
        )
        .await?;
    let next_xonly = next_user.x_only_public_key().to_string();
    let next_id = registry::get_signer_id(runtime, &next_xonly)
        .await?
        .expect("next user must have a signer_id");
    assert_eq!(
        next_id,
        user_id + 1,
        "rejected duplicate must not consume an ID (no gap)"
    );

    Ok(())
}

/// Wrong-length `schnorr_sig` and `bls_sig` in a `BlsBulkOp::RegisterBlsKey`
/// pass aggregate verification (those fields aren't used for BLS pubkey
/// resolution) but must be rejected by `register_bls_key`'s length checks
/// with no registry entry created.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_malformed_sig_lengths_in_bls_bulk_rejected_regtest() -> Result<()> {
    let user = reg_tester.unregistered_identity().await?;
    let mut publisher = reg_tester.unregistered_identity().await?;

    let bls_sk = blst::min_sig::SecretKey::from_bytes(&user.bls_secret_key).unwrap();
    let bls_pk_bytes = bls_sk.sk_to_pk().to_bytes().to_vec();
    let user_xonly = user.x_only_public_key().to_string();

    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("short schnorr_sig", vec![0u8; 32], vec![0u8; 48]),
        ("long schnorr_sig", vec![0u8; 128], vec![0u8; 48]),
        ("short bls_sig", vec![0u8; 64], vec![0u8; 24]),
        ("long bls_sig", vec![0u8; 64], vec![0u8; 96]),
    ];

    for (label, schnorr_sig, bls_sig) in cases {
        let op = AggregateInst {
            signer: SignerRef::XOnlyPubKey(user_xonly.clone()),
            inst: Inst::RegisterBlsKey {
                bls_pubkey: bls_pk_bytes.clone(),
                schnorr_sig,
                bls_sig,
            },
        };
        let msg = op.signing_message()?;
        let sig = bls_sk.sign(&msg, KONTOR_BLS_DST, &[]);
        let agg = AggregateSignature::aggregate(&[&sig], true).unwrap();

        let _ = reg_tester
            .instruction_envelope(
                &mut publisher,
                aggregate_envelope(vec![op], agg.to_signature().to_bytes().to_vec()),
            )
            .await;

        assert_eq!(
            registry::get_signer_id(runtime, &user_xonly).await?,
            None,
            "{label}: malformed field must prevent registration"
        );
    }

    Ok(())
}
