//! BLS attack vector tests.
//!
//! Tests that verify the Kontor BLS registration and aggregation scheme
//! is resistant to known attacks:
//! - Rogue-key attacks (Boneh, Drijvers, Neven 2018; <https://eprint.iacr.org/2018/483>)
//! - Proof replay across identities
//! - Aggregate-level forgery with same vs distinct messages

use anyhow::Result;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::rand::RngCore;
use bitcoin::key::{Secp256k1, rand};
use bitcoin::secp256k1::Message;
use blst::min_sig::SecretKey as BlsSecretKey;
use indexer::bls::{BLS_BINDING_PREFIX, KONTOR_BLS_DST, RegistrationProof, SCHNORR_BINDING_PREFIX};
use indexer::test_utils::bls_test::construct_rogue_g2_pubkey;
use indexer_types::Inst;
use testlib::*;

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_attack_rogue_key_registration_rejected() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let victim = rt.identity().await?;
    let victim_xonly = victim.x_only_public_key().to_string();

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
        rt.get_bls_pubkey(&attacker_xonly).await?,
        None,
        "rogue key must not be registered"
    );
    assert_eq!(
        rt.get_bls_pubkey(&victim_xonly).await?,
        Some(victim.bls_pubkey.to_vec()),
        "victim's registered key must be unchanged"
    );

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_attack_proof_replay_rejected() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();
    let alice = rt.identity().await?;
    let alice_xonly = alice.x_only_public_key().to_string();
    let alice_proof = RegistrationProof::new(&alice.keypair, &alice.bls_secret_key)?;

    let mut eve = rt.unregistered_identity().await?;
    let secp = Secp256k1::new();
    let eve_schnorr_msg = {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(&alice.bls_pubkey);
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
                bls_pubkey: alice.bls_pubkey.to_vec(),
                schnorr_sig: eve_schnorr_sig.to_vec(),
                bls_sig: alice_proof.bls_sig.to_vec(),
            },
        )
        .await;

    let eve_xonly = eve.x_only_public_key().to_string();
    assert_eq!(
        rt.get_bls_pubkey(&eve_xonly).await?,
        None,
        "replayed proof must not register Eve"
    );
    assert_eq!(
        rt.get_bls_pubkey(&alice_xonly).await?,
        Some(alice.bls_pubkey.to_vec()),
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
        rt.get_bls_pubkey(&eve_xonly).await?,
        None,
        "forged BLS binding must prevent registration"
    );

    Ok(())
}
