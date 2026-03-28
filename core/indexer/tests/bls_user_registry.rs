use anyhow::Result;
use blst::min_sig::SecretKey as BlsSecretKey;
use indexer::bls::RegistrationProof;
use indexer_types::Inst;
use testlib::*;

import!(
    name = "registry",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
);

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

/// Two users register via the direct path (separate transactions). `RegisterBlsKey`
/// is not available on the aggregate path; sequential direct registration replaces
/// the old single-tx `BlsBulk` with two `RegisterBlsKey` ops.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_register_in_bls_bulk_regtest() -> Result<()> {
    let mut user1 = reg_tester.unregistered_identity().await?;
    let mut user2 = reg_tester.unregistered_identity().await?;

    let proof1 = RegistrationProof::new(&user1.keypair, &user1.bls_secret_key)?;
    let proof2 = RegistrationProof::new(&user2.keypair, &user2.bls_secret_key)?;

    reg_tester
        .instruction(
            &mut user1,
            Inst::RegisterBlsKey {
                bls_pubkey: proof1.bls_pubkey.to_vec(),
                schnorr_sig: proof1.schnorr_sig.to_vec(),
                bls_sig: proof1.bls_sig.to_vec(),
            },
        )
        .await?;

    reg_tester
        .instruction(
            &mut user2,
            Inst::RegisterBlsKey {
                bls_pubkey: proof2.bls_pubkey.to_vec(),
                schnorr_sig: proof2.schnorr_sig.to_vec(),
                bls_sig: proof2.bls_sig.to_vec(),
            },
        )
        .await?;

    let xonly1 = user1.x_only_public_key().to_string();
    let xonly2 = user2.x_only_public_key().to_string();
    let user1_id = registry::get_signer_id(runtime, &xonly1)
        .await?
        .expect("user1 must have a signer_id");
    let user2_id = registry::get_signer_id(runtime, &xonly2)
        .await?
        .expect("user2 must have a signer_id");

    assert_eq!(
        user2_id,
        user1_id + 1,
        "second registration must get sequential signer_id"
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

/// Two direct `RegisterBlsKey` submissions for the same x-only with the SAME BLS key.
/// The first creates the registry entry; the second hits the idempotent early-return.
/// The result must be exactly one entry with one signer ID, and a subsequent
/// registration must get the next sequential ID (no gap).
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_duplicate_same_key_in_bundle_idempotent_regtest() -> Result<()> {
    let mut user = reg_tester.unregistered_identity().await?;

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    let user_xonly = user.x_only_public_key().to_string();

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

    let user_id = registry::get_signer_id(runtime, &user_xonly)
        .await?
        .expect("user must have a signer_id");
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

/// Two direct `RegisterBlsKey` submissions for the same x-only with DIFFERENT BLS keys.
/// The first registration succeeds; the second is rejected by the registry
/// ("BLS pubkey already registered for signer"). The original key must remain,
/// and no ID gap is created.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_different_keys_same_xonly_in_bundle_first_wins_regtest() -> Result<()> {
    let mut user = reg_tester.unregistered_identity().await?;

    let proof_a = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;

    let mut alt_ikm = [0u8; 32];
    alt_ikm[0] = 0xBB;
    let alt_sk = BlsSecretKey::key_gen(&alt_ikm, &[]).expect("alt key_gen");
    let proof_b = RegistrationProof::new(&user.keypair, &alt_sk.to_bytes())?;

    let user_xonly = user.x_only_public_key().to_string();

    reg_tester
        .instruction(
            &mut user,
            Inst::RegisterBlsKey {
                bls_pubkey: proof_a.bls_pubkey.to_vec(),
                schnorr_sig: proof_a.schnorr_sig.to_vec(),
                bls_sig: proof_a.bls_sig.to_vec(),
            },
        )
        .await?;

    let _ = reg_tester
        .instruction(
            &mut user,
            Inst::RegisterBlsKey {
                bls_pubkey: proof_b.bls_pubkey.to_vec(),
                schnorr_sig: proof_b.schnorr_sig.to_vec(),
                bls_sig: proof_b.bls_sig.to_vec(),
            },
        )
        .await;

    let user_id = registry::get_signer_id(runtime, &user_xonly)
        .await?
        .expect("user must have a signer_id");
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

/// Wrong-length `schnorr_sig` and `bls_sig` on a direct `RegisterBlsKey` must be
/// rejected by `register_bls_key`'s length checks. The signer entry may still be
/// created by `ensure_signer`, but no BLS key may be bound and nonce must stay 0.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_malformed_sig_lengths_in_bls_bulk_rejected_regtest() -> Result<()> {
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("short schnorr_sig", vec![0u8; 32], vec![0u8; 48]),
        ("long schnorr_sig", vec![0u8; 128], vec![0u8; 48]),
        ("short bls_sig", vec![0u8; 64], vec![0u8; 24]),
        ("long bls_sig", vec![0u8; 64], vec![0u8; 96]),
    ];

    for (label, schnorr_sig, bls_sig) in cases {
        let mut user = reg_tester.unregistered_identity().await?;
        let bls_sk = blst::min_sig::SecretKey::from_bytes(&user.bls_secret_key).unwrap();
        let bls_pk_bytes = bls_sk.sk_to_pk().to_bytes().to_vec();
        let user_xonly = user.x_only_public_key().to_string();

        assert_eq!(
            registry::get_signer_id(runtime, &user_xonly).await?,
            None,
            "{label}: test precondition failed, user must start unregistered"
        );

        let _ = reg_tester
            .instruction(
                &mut user,
                Inst::RegisterBlsKey {
                    bls_pubkey: bls_pk_bytes.clone(),
                    schnorr_sig,
                    bls_sig,
                },
            )
            .await;

        let signer_id = registry::get_signer_id(runtime, &user_xonly).await?;
        assert!(
            signer_id.is_some(),
            "{label}: signer entry should still exist after ensure_signer"
        );
        assert_eq!(
            registry::get_bls_pubkey(runtime, &user_xonly).await?,
            None,
            "{label}: malformed field must not bind a BLS pubkey"
        );
        let entry = registry::get_entry(runtime, &user_xonly)
            .await?
            .expect("entry must exist after ensure_signer");
        assert_eq!(
            entry.next_nonce, 0,
            "{label}: malformed field must not advance nonce"
        );
    }

    Ok(())
}

/// If a signer entry already exists without a BLS binding, malformed registration
/// must leave the signer_id, empty BLS binding, and nonce unchanged.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_user_registry_malformed_sig_lengths_preserve_existing_signer_entry_regtest()
-> Result<()> {
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("short schnorr_sig", vec![0u8; 32], vec![0u8; 48]),
        ("long schnorr_sig", vec![0u8; 128], vec![0u8; 48]),
        ("short bls_sig", vec![0u8; 64], vec![0u8; 24]),
        ("long bls_sig", vec![0u8; 64], vec![0u8; 96]),
    ];

    for (label, schnorr_sig, bls_sig) in cases {
        let mut user = reg_tester.unregistered_identity().await?;
        let bls_sk = blst::min_sig::SecretKey::from_bytes(&user.bls_secret_key).unwrap();
        let bls_pk_bytes = bls_sk.sk_to_pk().to_bytes().to_vec();
        let user_xonly = user.x_only_public_key().to_string();

        reg_tester.instruction(&mut user, Inst::Issuance).await?;

        let entry_before = registry::get_entry(runtime, &user_xonly)
            .await?
            .expect("issuance should create signer entry");
        assert_eq!(
            entry_before.bls_pubkey, None,
            "{label}: precondition failed, signer entry must not have a BLS key yet"
        );
        assert_eq!(
            entry_before.next_nonce, 0,
            "{label}: precondition failed, issuance must not advance nonce"
        );

        let _ = reg_tester
            .instruction(
                &mut user,
                Inst::RegisterBlsKey {
                    bls_pubkey: bls_pk_bytes.clone(),
                    schnorr_sig,
                    bls_sig,
                },
            )
            .await;

        let entry_after = registry::get_entry(runtime, &user_xonly)
            .await?
            .expect("signer entry must still exist");
        assert_eq!(
            entry_after.signer_id, entry_before.signer_id,
            "{label}: malformed field must not change signer_id"
        );
        assert_eq!(
            entry_after.bls_pubkey, None,
            "{label}: malformed field must not bind a BLS pubkey"
        );
        assert_eq!(
            entry_after.next_nonce, 0,
            "{label}: malformed field must not advance nonce"
        );
    }

    Ok(())
}
