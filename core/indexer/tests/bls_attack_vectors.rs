//! BLS attack vector tests.
//!
//! Tests that verify the Kontor BLS registration and aggregation scheme
//! is resistant to known attacks:
//! - Rogue-key attacks (Boneh, Drijvers, Neven 2018; <https://eprint.iacr.org/2018/483>)
//! - Proof replay across identities
//! - Aggregate-level forgery with same vs distinct messages

use anyhow::Result;
use bitcoin::Network;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::rand::RngCore;
use bitcoin::key::{Keypair, Secp256k1, rand};
use bitcoin::secp256k1::Message;
use blst::BLST_ERROR;
use blst::min_sig::SecretKey as BlsSecretKey;
use blst::min_sig::{AggregatePublicKey, AggregateSignature, PublicKey as BlsPublicKey};
use indexer::bls::{
    BLS_BINDING_PREFIX, KONTOR_BLS_DST, RegistrationProof, SCHNORR_BINDING_PREFIX,
    bls_derivation_path, derive_bls_secret_key_eip2333, validate_aggregate_shape,
};
use indexer_types::{AggregateInfo, Inst, Insts, Signer};
use testlib::{
    AnyhowError, ContractAddress, Decimal, Error, Integer, RawFileDescriptor, Runtime, TypedCall,
    import,
};

import!(
    name = "registry",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
);

fn derive_test_key(seed_byte: u8) -> blst::min_sig::SecretKey {
    let seed = [seed_byte; 64];
    derive_bls_secret_key_eip2333(&seed, &bls_derivation_path(Network::Regtest))
        .expect("failed to derive EIP-2333 secret key")
}

/// Construct PK_rogue = PK_beta − PK_victim in G2.
fn construct_rogue_g2_pubkey(
    beta_pk_compressed: &[u8; 96],
    victim_pk_compressed: &[u8; 96],
) -> [u8; 96] {
    let beta_pk = BlsPublicKey::key_validate(beta_pk_compressed).expect("beta pk must be valid G2");
    let mut neg_victim_bytes = *victim_pk_compressed;
    neg_victim_bytes[0] ^= 0x20;
    let neg_victim_pk =
        BlsPublicKey::key_validate(&neg_victim_bytes).expect("negated victim pk must be valid G2");
    let agg = AggregatePublicKey::aggregate(&[&beta_pk, &neg_victim_pk], false)
        .expect("aggregation must succeed");
    agg.to_public_key().to_bytes()
}

#[test]
fn rogue_key_forgery_succeeds_with_same_message() {
    let victim_sk = derive_test_key(10);
    let victim_pk = victim_sk.sk_to_pk();

    let beta_sk = derive_test_key(11);
    let beta_pk = beta_sk.sk_to_pk();

    let rogue_pk_bytes = construct_rogue_g2_pubkey(&beta_pk.to_bytes(), &victim_pk.to_bytes());
    let rogue_pk = blst::min_sig::PublicKey::key_validate(&rogue_pk_bytes)
        .expect("rogue key must be valid G2");

    let msg = b"identical-message";
    let forged_sig = beta_sk.sign(msg, KONTOR_BLS_DST, &[]);

    let result = forged_sig.aggregate_verify(
        true,
        &[msg.as_slice(), msg.as_slice()],
        KONTOR_BLS_DST,
        &[&rogue_pk, &victim_pk],
        true,
    );
    assert_eq!(
        result,
        BLST_ERROR::BLST_SUCCESS,
        "same-message rogue-key forgery must succeed (this is the attack)"
    );
}

#[test]
fn rogue_key_forgery_fails_with_distinct_messages() {
    let victim_sk = derive_test_key(10);
    let victim_pk = victim_sk.sk_to_pk();

    let beta_sk = derive_test_key(11);
    let beta_pk = beta_sk.sk_to_pk();

    let rogue_pk_bytes = construct_rogue_g2_pubkey(&beta_pk.to_bytes(), &victim_pk.to_bytes());
    let rogue_pk = blst::min_sig::PublicKey::key_validate(&rogue_pk_bytes)
        .expect("rogue key must be valid G2");

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
    assert_ne!(
        result,
        BLST_ERROR::BLST_SUCCESS,
        "distinct-message rogue-key forgery must fail"
    );
}

#[test]
fn bls_attack_eve_registers_own_key_under_alice_identity_aggregate_rejected() {
    let secp = Secp256k1::new();
    let alice_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let eve_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let alice_xonly = alice_keypair.x_only_public_key().0;

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

    let err = validate_aggregate_shape(&insts)
        .expect_err("aggregate RegisterBlsKey must be rejected before execution");
    assert!(
        err.to_string()
            .contains("RegisterBlsKey is not allowed in aggregate"),
        "aggregate registration path should be closed entirely"
    );
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_attack_rogue_key_registration_rejected() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut victim = rt.unregistered_identity().await?;
    let victim_proof = RegistrationProof::new(&victim.keypair, &victim.bls_secret_key)?;
    rt.instruction(
        &mut victim,
        Inst::RegisterBlsKey {
            bls_pubkey: victim_proof.bls_pubkey.to_vec(),
            schnorr_sig: victim_proof.schnorr_sig.to_vec(),
            bls_sig: victim_proof.bls_sig.to_vec(),
        },
    )
    .await?;

    let victim_xonly = victim.x_only_public_key().to_string();
    assert!(
        registry::get_signer_id(runtime, &victim_xonly)
            .await?
            .is_some(),
        "Victim must be registered"
    );

    let mut beta_ikm = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut beta_ikm);
    let beta_sk = BlsSecretKey::key_gen(&beta_ikm, &[]).expect("beta key_gen");
    let beta_pk_bytes = beta_sk.sk_to_pk().to_bytes();
    let rogue_pk_bytes = construct_rogue_g2_pubkey(&beta_pk_bytes, &victim.bls_pubkey);

    assert!(
        blst::min_sig::PublicKey::key_validate(&rogue_pk_bytes).is_ok(),
        "rogue key must be a valid G2 subgroup element"
    );

    let mut attacker = rt.unregistered_identity().await?;
    let secp = Secp256k1::new();

    let schnorr_msg = {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(&rogue_pk_bytes);
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        Message::from_digest_slice(&digest).expect("32-byte digest")
    };
    let schnorr_sig = secp
        .sign_schnorr(&schnorr_msg, &attacker.keypair)
        .serialize();

    let bls_binding_msg = {
        let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + 32);
        msg.extend_from_slice(BLS_BINDING_PREFIX);
        msg.extend_from_slice(&attacker.keypair.x_only_public_key().0.serialize());
        msg
    };
    let forged_bls_sig = beta_sk
        .sign(&bls_binding_msg, KONTOR_BLS_DST, &[])
        .to_bytes();

    let _ = rt
        .instruction(
            &mut attacker,
            Inst::RegisterBlsKey {
                bls_pubkey: rogue_pk_bytes.to_vec(),
                schnorr_sig: schnorr_sig.to_vec(),
                bls_sig: forged_bls_sig.to_vec(),
            },
        )
        .await;

    let attacker_xonly = attacker.x_only_public_key().to_string();
    assert_eq!(
        registry::get_bls_pubkey(runtime, &attacker_xonly).await?,
        None,
        "rogue key must not be registered"
    );
    assert_eq!(
        registry::get_bls_pubkey(runtime, &victim_xonly).await?,
        Some(victim_proof.bls_pubkey.to_vec()),
        "victim's registered key must be unchanged"
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_attack_proof_replay_rejected() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut alice = rt.unregistered_identity().await?;
    let alice_proof = RegistrationProof::new(&alice.keypair, &alice.bls_secret_key)?;
    rt.instruction(
        &mut alice,
        Inst::RegisterBlsKey {
            bls_pubkey: alice_proof.bls_pubkey.to_vec(),
            schnorr_sig: alice_proof.schnorr_sig.to_vec(),
            bls_sig: alice_proof.bls_sig.to_vec(),
        },
    )
    .await?;

    let alice_xonly = alice.x_only_public_key().to_string();
    assert!(
        registry::get_signer_id(runtime, &alice_xonly)
            .await?
            .is_some(),
        "Alice must be registered before the replay attempt"
    );

    let mut eve = rt.unregistered_identity().await?;
    let secp = Secp256k1::new();
    let eve_schnorr_msg = {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(&alice_proof.bls_pubkey);
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        Message::from_digest_slice(&digest).expect("32-byte digest")
    };
    let eve_schnorr_sig = secp
        .sign_schnorr(&eve_schnorr_msg, &eve.keypair)
        .serialize();

    let _ = rt
        .instruction(
            &mut eve,
            Inst::RegisterBlsKey {
                bls_pubkey: alice_proof.bls_pubkey.to_vec(),
                schnorr_sig: eve_schnorr_sig.to_vec(),
                bls_sig: alice_proof.bls_sig.to_vec(),
            },
        )
        .await;

    let eve_xonly = eve.x_only_public_key().to_string();
    assert_eq!(
        registry::get_bls_pubkey(runtime, &eve_xonly).await?,
        None,
        "replayed proof must not register Eve"
    );
    assert_eq!(
        registry::get_bls_pubkey(runtime, &alice_xonly).await?,
        Some(alice_proof.bls_pubkey.to_vec()),
        "Alice's registered key must be unchanged"
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_attack_valid_schnorr_forged_bls_binding() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let mut eve = rt.unregistered_identity().await?;

    let eve_bls_sk = BlsSecretKey::from_bytes(&eve.bls_secret_key).unwrap();
    let eve_bls_pk = eve_bls_sk.sk_to_pk();

    let mut alt_ikm = [0u8; 32];
    alt_ikm[0] = 0xAB;
    let alt_bls_sk = BlsSecretKey::key_gen(&alt_ikm, &[]).expect("alt key_gen");

    let secp = Secp256k1::new();
    let schnorr_msg = {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(&eve_bls_pk.to_bytes());
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        Message::from_digest_slice(&digest).expect("32-byte digest")
    };
    let schnorr_sig = secp.sign_schnorr(&schnorr_msg, &eve.keypair).serialize();

    let bls_binding_msg = {
        let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + 32);
        msg.extend_from_slice(BLS_BINDING_PREFIX);
        msg.extend_from_slice(&eve.keypair.x_only_public_key().0.serialize());
        msg
    };
    let forged_bls_sig = alt_bls_sk
        .sign(&bls_binding_msg, KONTOR_BLS_DST, &[])
        .to_bytes();

    let _ = rt
        .instruction(
            &mut eve,
            Inst::RegisterBlsKey {
                bls_pubkey: eve_bls_pk.to_bytes().to_vec(),
                schnorr_sig: schnorr_sig.to_vec(),
                bls_sig: forged_bls_sig.to_vec(),
            },
        )
        .await;

    let eve_xonly = eve.x_only_public_key().to_string();
    assert_eq!(
        registry::get_bls_pubkey(runtime, &eve_xonly).await?,
        None,
        "forged BLS binding must prevent registration"
    );

    Ok(())
}
