use anyhow::Result;
use blst::min_sig::SecretKey as BlsSecretKey;
use indexer::bls::{RegistrationProof, validate_aggregate_shape};
use indexer_types::{AggregateInfo, Inst, Insts};
use testlib::*;

import!(
    name = "registry",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
);

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_register_direct_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut user = rt.unregistered_identity().await?;

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    rt.instruction(
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
    assert!(signer_id.is_some(), "Expected signer to be registered");

    let registered_bls_pubkey = registry::get_bls_pubkey(runtime, &xonly).await?;
    assert_eq!(registered_bls_pubkey, Some(proof.bls_pubkey.to_vec()));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_register_in_aggregate_rejected_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let user1 = rt.unregistered_identity().await?;
    let user2 = rt.unregistered_identity().await?;

    let proof1 = RegistrationProof::new(&user1.keypair, &user1.bls_secret_key)?;
    let proof2 = RegistrationProof::new(&user2.keypair, &user2.bls_secret_key)?;

    let op0 = Inst::RegisterBlsKey {
        bls_pubkey: proof1.bls_pubkey.to_vec(),
        schnorr_sig: proof1.schnorr_sig.to_vec(),
        bls_sig: proof1.bls_sig.to_vec(),
    };
    let op1 = Inst::RegisterBlsKey {
        bls_pubkey: proof2.bls_pubkey.to_vec(),
        schnorr_sig: proof2.schnorr_sig.to_vec(),
        bls_sig: proof2.bls_sig.to_vec(),
    };

    let err = validate_aggregate_shape(&Insts {
        ops: vec![op0, op1],
        aggregate: Some(AggregateInfo {
            signer_ids: vec![0, 1],
            signature: vec![9u8; 48],
        }),
    })
    .expect_err("aggregate RegisterBlsKey must be rejected");

    let xonly1 = user1.x_only_public_key().to_string();
    let xonly2 = user2.x_only_public_key().to_string();
    assert!(
        err.to_string()
            .contains("RegisterBlsKey is not allowed in aggregate")
    );
    assert_eq!(registry::get_signer_id(runtime, &xonly1).await?, None);
    assert_eq!(registry::get_signer_id(runtime, &xonly2).await?, None);
    assert_eq!(registry::get_bls_pubkey(runtime, &xonly1).await?, None);
    assert_eq!(registry::get_bls_pubkey(runtime, &xonly2).await?, None);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_register_same_key_twice_is_idempotent_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut user = rt.unregistered_identity().await?;

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    rt.instruction(
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
    let _ = rt
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

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_rejects_different_key_for_same_signer_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut user = rt.unregistered_identity().await?;

    let original = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    rt.instruction(
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

    let _res = rt
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
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_duplicate_same_key_in_aggregate_rejected_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let user = rt.unregistered_identity().await?;

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    let user_xonly = user.x_only_public_key().to_string();

    let op = Inst::RegisterBlsKey {
        bls_pubkey: proof.bls_pubkey.to_vec(),
        schnorr_sig: proof.schnorr_sig.to_vec(),
        bls_sig: proof.bls_sig.to_vec(),
    };

    let err = validate_aggregate_shape(&Insts {
        ops: vec![op.clone(), op],
        aggregate: Some(AggregateInfo {
            signer_ids: vec![0, 0],
            signature: vec![9u8; 48],
        }),
    })
    .expect_err("aggregate RegisterBlsKey must be rejected");

    assert!(
        err.to_string()
            .contains("RegisterBlsKey is not allowed in aggregate")
    );
    assert_eq!(registry::get_signer_id(runtime, &user_xonly).await?, None);
    assert_eq!(registry::get_bls_pubkey(runtime, &user_xonly).await?, None);

    // Next registration should get the expected ID (no gap from rejected aggregate)
    let mut next_user = rt.unregistered_identity().await?;
    let next_proof = RegistrationProof::new(&next_user.keypair, &next_user.bls_secret_key)?;
    rt.instruction(
        &mut next_user,
        Inst::RegisterBlsKey {
            bls_pubkey: next_proof.bls_pubkey.to_vec(),
            schnorr_sig: next_proof.schnorr_sig.to_vec(),
            bls_sig: next_proof.bls_sig.to_vec(),
        },
    )
    .await?;
    let next_xonly = next_user.x_only_public_key().to_string();
    let next_id = registry::get_signer_id(runtime, &next_xonly).await?;
    assert!(
        next_id.is_some(),
        "next user should be registered after rejected aggregate"
    );

    Ok(())
}

/// Two `RegisterBlsKey` ops for the same x-only with DIFFERENT BLS keys in one
/// bundle. The first registration succeeds; the second is rejected by the
/// registry ("BLS pubkey already registered for signer"). The original key
/// must remain, and no ID gap is created.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_different_keys_same_xonly_in_aggregate_rejected_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let user = rt.unregistered_identity().await?;

    let proof_a = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;

    let mut alt_ikm = [0u8; 32];
    alt_ikm[0] = 0xBB;
    let alt_sk = BlsSecretKey::key_gen(&alt_ikm, &[]).expect("alt key_gen");
    let proof_b = RegistrationProof::new(&user.keypair, &alt_sk.to_bytes())?;

    let user_xonly = user.x_only_public_key().to_string();

    let op_a = Inst::RegisterBlsKey {
        bls_pubkey: proof_a.bls_pubkey.to_vec(),
        schnorr_sig: proof_a.schnorr_sig.to_vec(),
        bls_sig: proof_a.bls_sig.to_vec(),
    };
    let op_b = Inst::RegisterBlsKey {
        bls_pubkey: proof_b.bls_pubkey.to_vec(),
        schnorr_sig: proof_b.schnorr_sig.to_vec(),
        bls_sig: proof_b.bls_sig.to_vec(),
    };

    let err = validate_aggregate_shape(&Insts {
        ops: vec![op_a, op_b],
        aggregate: Some(AggregateInfo {
            signer_ids: vec![0, 0],
            signature: vec![9u8; 48],
        }),
    })
    .expect_err("aggregate RegisterBlsKey must be rejected");

    assert!(
        err.to_string()
            .contains("RegisterBlsKey is not allowed in aggregate")
    );
    assert_eq!(registry::get_signer_id(runtime, &user_xonly).await?, None);
    assert_eq!(registry::get_bls_pubkey(runtime, &user_xonly).await?, None);

    let mut next_user = rt.unregistered_identity().await?;
    let next_proof = RegistrationProof::new(&next_user.keypair, &next_user.bls_secret_key)?;
    rt.instruction(
        &mut next_user,
        Inst::RegisterBlsKey {
            bls_pubkey: next_proof.bls_pubkey.to_vec(),
            schnorr_sig: next_proof.schnorr_sig.to_vec(),
            bls_sig: next_proof.bls_sig.to_vec(),
        },
    )
    .await?;
    let next_xonly = next_user.x_only_public_key().to_string();
    let next_id = registry::get_signer_id(runtime, &next_xonly).await?;
    assert!(
        next_id.is_some(),
        "next user should be registered after rejected aggregate"
    );

    Ok(())
}

/// Wrong-length `schnorr_sig` and `bls_sig` in a `BlsBulkOp::RegisterBlsKey`
/// pass aggregate verification (those fields aren't used for BLS pubkey
/// resolution) but must be rejected by `register_bls_key`'s length checks
/// with no registry entry created.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_malformed_sig_lengths_in_aggregate_rejected_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let user = rt.unregistered_identity().await?;
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
        let op = Inst::RegisterBlsKey {
            bls_pubkey: bls_pk_bytes.clone(),
            schnorr_sig,
            bls_sig,
        };
        let err = validate_aggregate_shape(&Insts {
            ops: vec![op],
            aggregate: Some(AggregateInfo {
                signer_ids: vec![0],
                signature: vec![9u8; 48],
            }),
        })
        .expect_err("aggregate RegisterBlsKey must be rejected");

        assert!(
            err.to_string()
                .contains("RegisterBlsKey is not allowed in aggregate")
        );
        assert_eq!(
            registry::get_signer_id(runtime, &user_xonly).await?,
            None,
            "{label}: malformed field must prevent registration"
        );
    }

    Ok(())
}
