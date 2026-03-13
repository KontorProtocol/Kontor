use anyhow::Result;
use bitcoin::key::rand::RngCore;
use bitcoin::key::{Secp256k1, rand};
use bitcoin::{Address, Network};
use blst::min_sig::AggregateSignature;
use blst::min_sig::SecretKey as BlsSecretKey;
use indexer::bls::{
    KONTOR_BLS_DST, RegistrationProof, bls_derivation_path, derive_bls_secret_key_eip2333,
    taproot_derivation_path,
};
use indexer::reg_tester::{Identity, RegTester, derive_taproot_keypair_from_seed};
use indexer_types::{BlsBulkOp, Inst, Signer};
use testlib::*;

import!(
    name = "registry",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
);

async fn unregistered_identity(reg_tester: &mut RegTester) -> Result<Identity> {
    let mut seed = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut seed);

    let taproot_path = taproot_derivation_path(Network::Regtest);
    let bls_path = bls_derivation_path(Network::Regtest);

    let keypair = derive_taproot_keypair_from_seed(&seed, &taproot_path)?;
    let secp = Secp256k1::new();
    let (x_only_public_key, ..) = keypair.x_only_public_key();
    let address = Address::p2tr(&secp, x_only_public_key, None, Network::Regtest);

    let bls_sk = derive_bls_secret_key_eip2333(&seed, &bls_path)?;
    let bls_secret_key = bls_sk.to_bytes();
    let bls_pubkey = bls_sk.sk_to_pk().to_bytes();

    let mut funded = reg_tester.fund_address(&address, 1).await?;
    let next_funding_utxo = funded
        .pop()
        .ok_or_else(|| anyhow!("failed to fund identity"))?;

    Ok(Identity {
        address,
        keypair,
        next_funding_utxo,
        bls_secret_key,
        bls_pubkey,
    })
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_register_direct_regtest() -> Result<()> {
    let mut user = unregistered_identity(&mut reg_tester).await?;

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
    let user1 = unregistered_identity(&mut reg_tester).await?;
    let user2 = unregistered_identity(&mut reg_tester).await?;
    let mut publisher = unregistered_identity(&mut reg_tester).await?;

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
    let mut user = unregistered_identity(&mut reg_tester).await?;

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
    let mut user = unregistered_identity(&mut reg_tester).await?;

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

/// Wrong-length `schnorr_sig` and `bls_sig` in a `BlsBulkOp::RegisterBlsKey`
/// pass aggregate verification (those fields aren't used for BLS pubkey
/// resolution) but must be rejected by `register_bls_key`'s length checks
/// with no registry entry created.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_malformed_sig_lengths_in_bls_bulk_rejected_regtest() -> Result<()> {
    let user = unregistered_identity(&mut reg_tester).await?;
    let mut publisher = unregistered_identity(&mut reg_tester).await?;

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
        let op = BlsBulkOp::RegisterBlsKey {
            signer: Signer::XOnlyPubKey(user_xonly.clone()),
            bls_pubkey: bls_pk_bytes.clone(),
            schnorr_sig,
            bls_sig,
        };
        let msg = op.signing_message()?;
        let sig = bls_sk.sign(&msg, KONTOR_BLS_DST, &[]);
        let agg = AggregateSignature::aggregate(&[&sig], true).unwrap();

        let _ = reg_tester
            .instruction(
                &mut publisher,
                Inst::BlsBulk {
                    ops: vec![op],
                    signature: agg.to_signature().to_bytes().to_vec(),
                },
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

