use anyhow::Result;
use blst::min_sig::AggregateSignature;
use blst::min_sig::SecretKey as BlsSecretKey;
use indexer::bls::KONTOR_BLS_DST;
use indexer::bls::RegistrationProof;
use indexer_types::{BlsBulkOp, Inst, Signer};
use testlib::*;

import!(
    name = "registry",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
);

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_register_direct_regtest() -> Result<()> {
    let mut user = reg_tester.identity().await?;

    reg_tester.instruction(&mut user, Inst::Issuance).await?;

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
    let mut user1 = reg_tester.identity().await?;
    let mut user2 = reg_tester.identity().await?;
    let mut publisher = reg_tester.identity().await?;

    reg_tester.instruction(&mut user1, Inst::Issuance).await?;
    reg_tester.instruction(&mut user2, Inst::Issuance).await?;
    reg_tester
        .instruction(&mut publisher, Inst::Issuance)
        .await?;

    let proof1 = RegistrationProof::new(&user1.keypair, &user1.bls_secret_key)?;
    let proof2 = RegistrationProof::new(&user2.keypair, &user2.bls_secret_key)?;

    let op0 = BlsBulkOp::RegisterBlsKey {
        signer: Signer::XOnlyPubKey(user1.x_only_public_key().to_string()),
        bls_pubkey: proof1.bls_pubkey.to_vec(),
        schnorr_sig: proof1.schnorr_sig.to_vec(),
        bls_sig: proof1.bls_sig.to_vec(),
    };
    let op1 = BlsBulkOp::RegisterBlsKey {
        signer: Signer::XOnlyPubKey(user2.x_only_public_key().to_string()),
        bls_pubkey: proof2.bls_pubkey.to_vec(),
        schnorr_sig: proof2.schnorr_sig.to_vec(),
        bls_sig: proof2.bls_sig.to_vec(),
    };

    let msg0 = op0.signing_message()?;
    let msg1 = op1.signing_message()?;

    let sk1 = blst::min_sig::SecretKey::from_bytes(&user1.bls_secret_key).unwrap();
    let sk2 = blst::min_sig::SecretKey::from_bytes(&user2.bls_secret_key).unwrap();
    let sig0 = sk1.sign(&msg0, KONTOR_BLS_DST, &[]);
    let sig1 = sk2.sign(&msg1, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig0, &sig1], true).unwrap();
    let aggregate_sig = aggregate.to_signature();

    let _res = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op0, op1],
                signature: aggregate_sig.to_bytes().to_vec(),
            },
        )
        .await?;

    let xonly1 = user1.x_only_public_key().to_string();
    let xonly2 = user2.x_only_public_key().to_string();
    assert_eq!(registry::get_signer_id(runtime, &xonly1).await?, Some(0));
    assert_eq!(registry::get_signer_id(runtime, &xonly2).await?, Some(1));
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
    let mut user = reg_tester.identity().await?;
    reg_tester.instruction(&mut user, Inst::Issuance).await?;

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

    let signer_id_after = registry::get_signer_id(runtime, &xonly).await?;
    let pk_after = registry::get_bls_pubkey(runtime, &xonly).await?;

    assert_eq!(signer_id_before, signer_id_after);
    assert_eq!(pk_before, pk_after);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_rejects_different_key_for_same_signer_regtest() -> Result<()> {
    let mut user = reg_tester.identity().await?;
    reg_tester.instruction(&mut user, Inst::Issuance).await?;

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
