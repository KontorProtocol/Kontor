use anyhow::Result;
use blst::min_sig::AggregateSignature;
use indexer::bls::{KONTOR_BLS_DST, RegistrationProof};
use indexer_types::{BlsBulkOp, Inst, Signer};
use testlib::*;

import!(
    name = "registry",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
);

const KONTOR_OP_PREFIX: &[u8] = b"KONTOR-OP-V1";

fn build_kontor_op_message(op: &BlsBulkOp) -> Result<Vec<u8>> {
    let op_bytes = indexer_types::serialize(op)?;
    let mut msg = Vec::with_capacity(KONTOR_OP_PREFIX.len() + op_bytes.len());
    msg.extend_from_slice(KONTOR_OP_PREFIX);
    msg.extend_from_slice(&op_bytes);
    Ok(msg)
}

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
    reg_tester.instruction(&mut publisher, Inst::Issuance).await?;

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

    let msg0 = build_kontor_op_message(&op0)?;
    let msg1 = build_kontor_op_message(&op1)?;

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

