use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::{Keypair, Secp256k1, rand};
use bitcoin::secp256k1::Message;
use blst::BLST_ERROR;
use blst::min_sig::AggregateSignature;
use indexer::bls::{
    BLS_BINDING_PREFIX, KONTOR_BLS_DST, SCHNORR_BINDING_PREFIX, validate_aggregate_shape,
};
use indexer::test_utils::bls_test::{construct_rogue_g2_pubkey, derive_test_key};
use indexer_types::{AggregateInfo, Inst, Insts};

#[test]
fn rogue_key_forgery_succeeds_with_same_message() {
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
