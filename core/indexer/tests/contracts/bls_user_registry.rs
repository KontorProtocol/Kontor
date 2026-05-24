use anyhow::{Result, anyhow};
use blst::min_sig::{AggregateSignature, SecretKey as BlsSecretKey};
use indexer::bls::{KONTOR_BLS_DST, RegistrationProof};
use indexer_types::{AggregateInfo, AggregateSigner, Inst, InstKind, Insts, SignerRef};
use testlib::*;

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_register_direct_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut user = rt.unregistered_identity().await?;

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    rt.instruction_insts(
        &mut user,
        Insts::direct(vec![
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Issuance,
            },
            Inst {
                gas_limit: 10_000,
                kind: InstKind::RegisterBlsKey {
                    bls_pubkey: proof.bls_pubkey.to_vec(),
                    schnorr_sig: proof.schnorr_sig.to_vec(),
                    bls_sig: proof.bls_sig.to_vec(),
                },
            },
        ]),
    )
    .await?;

    let xonly = user.x_only_public_key().to_string();
    let signer_id = rt.get_signer_id(&xonly).await?;
    assert!(signer_id.is_some(), "Expected signer to be registered");

    let registered_bls_pubkey = rt.get_bls_pubkey(&xonly).await?;
    assert_eq!(registered_bls_pubkey, Some(proof.bls_pubkey.to_vec()));

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_register_same_key_twice_is_idempotent_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut user = rt.unregistered_identity().await?;

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    rt.instruction_insts(
        &mut user,
        Insts::direct(vec![
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Issuance,
            },
            Inst {
                gas_limit: 10_000,
                kind: InstKind::RegisterBlsKey {
                    bls_pubkey: proof.bls_pubkey.to_vec(),
                    schnorr_sig: proof.schnorr_sig.to_vec(),
                    bls_sig: proof.bls_sig.to_vec(),
                },
            },
        ]),
    )
    .await?;

    let xonly = user.x_only_public_key().to_string();
    let signer_id_before = rt.get_signer_id(&xonly).await?;
    let pk_before = rt.get_bls_pubkey(&xonly).await?;

    // Second registration with same key hits the early-return optimization in
    // register_bls_key, so no contract result is recorded. Ignore the result-lookup error.
    let _ = rt
        .instruction(
            &mut user,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::RegisterBlsKey {
                    bls_pubkey: proof.bls_pubkey.to_vec(),
                    schnorr_sig: proof.schnorr_sig.to_vec(),
                    bls_sig: proof.bls_sig.to_vec(),
                },
            },
        )
        .await;

    let signer_id_after = rt.get_signer_id(&xonly).await?;
    let pk_after = rt.get_bls_pubkey(&xonly).await?;

    assert_eq!(signer_id_before, signer_id_after);
    assert_eq!(pk_before, pk_after);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_rejects_different_key_for_same_signer_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut user = rt.unregistered_identity().await?;

    let original = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    rt.instruction_insts(
        &mut user,
        Insts::direct(vec![
            Inst {
                gas_limit: 10_000,
                kind: InstKind::Issuance,
            },
            Inst {
                gas_limit: 10_000,
                kind: InstKind::RegisterBlsKey {
                    bls_pubkey: original.bls_pubkey.to_vec(),
                    schnorr_sig: original.schnorr_sig.to_vec(),
                    bls_sig: original.bls_sig.to_vec(),
                },
            },
        ]),
    )
    .await?;

    let mut ikm = [0u8; 32];
    ikm[0] = 99;
    let alt_sk = BlsSecretKey::key_gen(&ikm, &[]).expect("alt key_gen");
    let alt_proof = RegistrationProof::new(&user.keypair, &alt_sk.to_bytes())?;

    let xonly = user.x_only_public_key().to_string();
    let signer_id_before = rt.get_signer_id(&xonly).await?;
    let pk_before = rt.get_bls_pubkey(&xonly).await?;

    // Registration with a different key is rejected by the runtime before
    // reaching the contract, so no op result is recorded. Ignore the error.
    let _ = rt
        .instruction(
            &mut user,
            Inst {
                gas_limit: 10_000,
                kind: InstKind::RegisterBlsKey {
                    bls_pubkey: alt_proof.bls_pubkey.to_vec(),
                    schnorr_sig: alt_proof.schnorr_sig.to_vec(),
                    bls_sig: alt_proof.bls_sig.to_vec(),
                },
            },
        )
        .await;

    let signer_id_after = rt.get_signer_id(&xonly).await?;
    let pk_after = rt.get_bls_pubkey(&xonly).await?;
    assert_eq!(signer_id_before, signer_id_after);
    assert_eq!(pk_before, pk_after);
    assert_eq!(pk_after, Some(original.bls_pubkey.to_vec()));
    Ok(())
}

/// Sponsored aggregate `RegisterBlsKey` end-to-end:
/// - publisher (registered, funded) submits a one-op aggregate
/// - op is `Sponsored`; aggregate carries `publisher_sponsorship`
/// - registrant is brand-new — identified by `SignerRef::XOnlyPubkey(x_only)`
/// - registrant signs over their own `SignerRef::XOnlyPubkey` (they don't yet
///   have a `signer_id` to sign over)
/// - aggregate verify uses the inline `bls_pubkey` from the Inst payload
///   (no DB row exists yet)
/// - after execution: bls_keys row exists for the new signer and the
///   payment was attributed to the publisher
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_register_in_aggregate_sponsored_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut publisher = rt.identity().await?;
    let user = rt.unregistered_identity().await?;

    let publisher_id = rt
        .get_signer_id(&publisher.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id for publisher"))?;
    let user_xonly_pk = user.x_only_public_key();
    let user_xonly_str = user_xonly_pk.to_string();

    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;

    let op = Inst {
        gas_limit: 10_000,
        kind: InstKind::RegisterBlsKey {
            bls_pubkey: proof.bls_pubkey.to_vec(),
            schnorr_sig: proof.schnorr_sig.to_vec(),
            bls_sig: proof.bls_sig.to_vec(),
        },
    };

    // Registrant signs over their own SignerRef::XOnlyPubkey — they don't
    // yet have a signer_id to sign over. They commit to `sponsored = true`
    // so the publisher can't unilaterally flip them to self-pay.
    let claim = SignerRef::XOnlyPubkey(user_xonly_pk);
    let msg = op.aggregate_signing_message(&claim, 0, true)?;
    let user_sk = BlsSecretKey::from_bytes(&user.bls_secret_key)
        .map_err(|e| anyhow!("invalid user BLS secret key: {e:?}"))?;
    let sig = user_sk.sign(&msg, KONTOR_BLS_DST, &[]);
    let aggregate_sig =
        AggregateSignature::aggregate(&[&sig], true).map_err(|e| anyhow!("aggregate: {e:?}"))?;

    let res = rt
        .instruction_insts(
            &mut publisher,
            Insts {
                ops: vec![op],
                aggregate: Some(AggregateInfo {
                    signers: vec![AggregateSigner {
                        identity: claim,
                        nonce: 0,
                        sponsored: true,
                    }],
                    signature: aggregate_sig.to_signature().to_bytes().to_vec(),
                }),
            },
        )
        .await?;

    // Registration landed: the new signer has a row and their BLS pubkey is bound.
    let new_signer_id = rt
        .get_signer_id(&user_xonly_str)
        .await?
        .ok_or_else(|| anyhow!("registrant should have a signer_id after aggregate"))?;
    let registered_bls = rt.get_bls_pubkey(&user_xonly_str).await?;
    assert_eq!(registered_bls, Some(proof.bls_pubkey.to_vec()));
    assert_ne!(
        new_signer_id, publisher_id,
        "registrant must be a distinct signer from the publisher"
    );

    // The publisher paid for the registration (gas attributed via the
    // registry.registered contract call), not the registrant.
    assert_eq!(
        res.result.payer_signer_id,
        Some(publisher_id as i64),
        "sponsored RegisterBlsKey gas must be charged to the publisher"
    );

    Ok(())
}

/// An existing signer (has a `signer_id` from prior direct activity, but no
/// bls_keys row) registers their BLS key via a sponsored aggregate using
/// `SignerRef::SignerId`. Guards a bug where `verify_aggregate` populated
/// `signer_map` only for the `SignerRef::XOnlyPubkey` path — leaving the
/// `Id`-claim case to be silently dropped by `process_aggregate_input`'s
/// `signer_map.contains_key` check after a successful BLS verify.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_user_registry_register_in_aggregate_via_id_claim_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut publisher = rt.identity().await?;
    let mut user = rt.unregistered_identity().await?;

    // Step 1: user does a direct Issuance to land in the signers table with a
    // known signer_id, but no bls_keys row yet.
    rt.instruction(
        &mut user,
        Inst {
            gas_limit: 10_000,
            kind: InstKind::Issuance,
        },
    )
    .await?;
    let user_xonly_str = user.x_only_public_key().to_string();
    let user_signer_id = rt
        .get_signer_id(&user_xonly_str)
        .await?
        .ok_or_else(|| anyhow!("user must have signer_id after Issuance"))?;
    assert_eq!(
        rt.get_bls_pubkey(&user_xonly_str).await?,
        None,
        "user must not yet have a registered BLS pubkey"
    );

    // Step 2: publisher submits a sponsored aggregate containing the user's
    // RegisterBlsKey, identifying the user via SignerRef::SignerId.
    let proof = RegistrationProof::new(&user.keypair, &user.bls_secret_key)?;
    let op = Inst {
        gas_limit: 10_000,
        kind: InstKind::RegisterBlsKey {
            bls_pubkey: proof.bls_pubkey.to_vec(),
            schnorr_sig: proof.schnorr_sig.to_vec(),
            bls_sig: proof.bls_sig.to_vec(),
        },
    };
    let claim = SignerRef::SignerId(user_signer_id);
    let msg = op.aggregate_signing_message(&claim, 0, true)?;
    let user_sk = BlsSecretKey::from_bytes(&user.bls_secret_key)
        .map_err(|e| anyhow!("invalid user BLS secret key: {e:?}"))?;
    let sig = user_sk.sign(&msg, KONTOR_BLS_DST, &[]);
    let aggregate_sig =
        AggregateSignature::aggregate(&[&sig], true).map_err(|e| anyhow!("aggregate: {e:?}"))?;

    rt.instruction_insts(
        &mut publisher,
        Insts {
            ops: vec![op],
            aggregate: Some(AggregateInfo {
                signers: vec![AggregateSigner {
                    identity: claim,
                    nonce: 0,
                    sponsored: true,
                }],
                signature: aggregate_sig.to_signature().to_bytes().to_vec(),
            }),
        },
    )
    .await?;

    assert_eq!(
        rt.get_bls_pubkey(&user_xonly_str).await?,
        Some(proof.bls_pubkey.to_vec()),
        "BLS pubkey should land in bls_keys after Id-claim aggregate registration"
    );
    Ok(())
}
