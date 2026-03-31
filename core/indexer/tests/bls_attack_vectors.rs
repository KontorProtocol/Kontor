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
    AnyhowError, ContractAddress, Decimal, Error, Integer, RawFileDescriptor, RegTester, Runtime,
    RuntimeConfig, import, serial_test,
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
///
/// Standard rogue-key construction (Boneh, Drijvers, Neven 2018;
/// <https://eprint.iacr.org/2018/483>). The attacker knows beta_sk but NOT the
/// discrete log of PK_rogue, so they cannot produce valid BLS signatures under it.
///
/// Without a binding proof / PoP, this key is dangerous: PK_rogue + PK_victim =
/// β·G2, so the attacker can forge aggregate signatures that appear to include
/// the victim by computing σ = β·H(m).
///
/// Kontor's defense is the BLS binding proof in [`RegistrationProof`], which is a
/// proper BLS signature (hash-to-curve random oracle). Unlike linear KOSK schemes
/// (e.g. ZK Hack IV "Supervillain"), the hash-to-curve makes each binding proof
/// algebraically independent — the attacker cannot combine existing proofs to
/// forge one for PK_rogue.
fn construct_rogue_g2_pubkey(
    beta_pk_compressed: &[u8; 96],
    victim_pk_compressed: &[u8; 96],
) -> [u8; 96] {
    let beta_pk = BlsPublicKey::key_validate(beta_pk_compressed).expect("beta pk must be valid G2");

    // Negate victim's pubkey by flipping the sign bit in compressed form.
    // BLS12-381 compressed points use bit 5 (0x20) to select which square
    // root of y² was used; flipping it gives (x, -y) = -P.
    let mut neg_victim_bytes = *victim_pk_compressed;
    neg_victim_bytes[0] ^= 0x20;
    let neg_victim_pk =
        BlsPublicKey::key_validate(&neg_victim_bytes).expect("negated victim pk must be valid G2");

    // PK_rogue = PK_beta + (-PK_victim)
    let agg = AggregatePublicKey::aggregate(&[&beta_pk, &neg_victim_pk], false)
        .expect("aggregation must succeed");
    agg.to_public_key().to_bytes()
}

// ---------------------------------------------------------------------------
// Unit tests — aggregate-level rogue-key properties
// ---------------------------------------------------------------------------

/// Proves the rogue-key attack IS real when two signers sign the same message.
/// The attacker forges σ = β·H(m) and it verifies as an aggregate of
/// [PK_rogue, PK_victim] — without the victim ever signing anything.
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

    // Attacker forges aggregate: σ = β·H(m). Victim never signed.
    let forged_sig = beta_sk.sign(msg, KONTOR_BLS_DST, &[]);

    // e(β·H(m), G2) = e(H(m), β·G2) = e(H(m), PK_rogue + PK_victim) ✓
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

/// Proves the attack fails when each operation has a distinct message, which is
/// always the case in Kontor (signer_id, nonce, and op contents differ).
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

    // Victim legitimately signed their op (e.g. broadcast to bundler).
    let victim_sig = victim_sk.sign(msg_victim, KONTOR_BLS_DST, &[]);
    // Attacker signs their op with β (only key they know).
    let attacker_sig = beta_sk.sign(msg_attacker, KONTOR_BLS_DST, &[]);

    let agg =
        AggregateSignature::aggregate(&[&attacker_sig, &victim_sig], true).expect("aggregate");
    let agg_sig = agg.to_signature();

    // Verification fails: e(H(msg_a), -PK_victim) · e(H(msg_v), PK_victim) ≠ 1
    // because H(msg_a) ≠ H(msg_v).
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

// ---------------------------------------------------------------------------
// Integration tests — registration-level attacks
// ---------------------------------------------------------------------------

/// Rogue-key attack: attacker constructs PK_rogue = β·G2 − PK_victim and tries
/// to register it. The BLS binding proof rejects this because the attacker does
/// not know dlog(PK_rogue) and therefore cannot sign the binding message.
///
/// Signing with β fails verification: e(β·H(msg), G2) ≠ e(H(msg), PK_rogue)
/// because PK_rogue ≠ β·G2.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_attack_rogue_key_registration_rejected_regtest() -> Result<()> {
    let mut victim = reg_tester.unregistered_identity().await?;
    let victim_proof = RegistrationProof::new(&victim.keypair, &victim.bls_secret_key)?;
    reg_tester
        .instruction(
            &mut victim,
            Inst::RegisterBlsKey {
                bls_pubkey: victim_proof.bls_pubkey.to_vec(),
                schnorr_sig: victim_proof.schnorr_sig.to_vec(),
                bls_sig: victim_proof.bls_sig.to_vec(),
            },
        )
        .await?;

    let victim_xonly = victim.x_only_public_key().to_string();
    assert_eq!(
        registry::get_signer_id(runtime, &victim_xonly).await?,
        Some(0)
    );

    // Attacker picks random β and constructs PK_rogue = β·G2 − PK_victim.
    let mut beta_ikm = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut beta_ikm);
    let beta_sk = BlsSecretKey::key_gen(&beta_ikm, &[]).expect("beta key_gen");
    let beta_pk_bytes = beta_sk.sk_to_pk().to_bytes();
    let rogue_pk_bytes = construct_rogue_g2_pubkey(&beta_pk_bytes, &victim.bls_pubkey);

    // PK_rogue is on-curve and in-subgroup — the rejection must come from the
    // binding proof, not from subgroup validation.
    assert!(
        blst::min_sig::PublicKey::key_validate(&rogue_pk_bytes).is_ok(),
        "rogue key must be a valid G2 subgroup element"
    );

    let mut attacker = reg_tester.unregistered_identity().await?;
    let secp = Secp256k1::new();

    // Schnorr half: attacker CAN produce (they own the Taproot key).
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

    // BLS half: attacker CANNOT produce — they know β, not dlog(PK_rogue).
    let bls_binding_msg = {
        let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + 32);
        msg.extend_from_slice(BLS_BINDING_PREFIX);
        msg.extend_from_slice(&attacker.keypair.x_only_public_key().0.serialize());
        msg
    };
    let forged_bls_sig = beta_sk
        .sign(&bls_binding_msg, KONTOR_BLS_DST, &[])
        .to_bytes();

    let _ = reg_tester
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

/// Proof replay: Eve takes Alice's (bls_pubkey, bls_sig) and submits them under
/// Eve's Taproot identity with Eve's own Schnorr signature. The BLS binding
/// proof signs `BLS_BINDING_PREFIX || alice_xonly`, so verification against
/// Eve's x-only pubkey fails.
///
/// This test would PASS (incorrectly allowing registration) if the BLS binding
/// message were changed to sign only the BLS pubkey without the x-only identity
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_attack_proof_replay_rejected_regtest() -> Result<()> {
    // Alice registers legitimately.
    let mut alice = reg_tester.unregistered_identity().await?;
    let alice_proof = RegistrationProof::new(&alice.keypair, &alice.bls_secret_key)?;
    reg_tester
        .instruction(
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

    // Eve creates her own Schnorr binding to Alice's BLS pubkey (she controls
    // her Taproot key, so this is trivial).
    let mut eve = reg_tester.unregistered_identity().await?;
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

    // Eve reuses Alice's BLS binding proof verbatim.
    // Alice's proof signed `BLS_BINDING_PREFIX || alice_xonly`, but the indexer
    // will verify it against eve_xonly — mismatch.
    let _ = reg_tester
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

/// Identity hijack via aggregate registration: Eve tries to register her own BLS key under
/// Alice's Taproot identity. Eve CAN produce the BLS binding proof (she signs
/// `BLS_BINDING_PREFIX || alice_xonly` with `eve_bls_sk`), but CANNOT produce
/// the Schnorr proof (needs Alice's Taproot secret key to sign over
/// `SCHNORR_BINDING_PREFIX || eve_bls_pk`).
///
/// | Proof half | Blocks Eve? | Why                                          |
/// |------------|-------------|----------------------------------------------|
/// | Schnorr    | **Yes**     | Needs Alice's Taproot sk                     |
/// | BLS        | No          | Eve can sign alice_xonly with her own BLS key |
/// In the current `Insts` / `AggregateInfo` model, aggregate `RegisterBlsKey`
/// is rejected outright before verification/execution, which removes this
/// attack surface from the bundled path entirely.
#[test]
fn bls_attack_eve_registers_own_key_under_alice_identity_aggregate_rejected() {
    let secp = Secp256k1::new();
    let alice_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let eve_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let alice_xonly = alice_keypair.x_only_public_key().0;

    let eve_bls_sk = derive_test_key(42);
    let eve_bls_pk = eve_bls_sk.sk_to_pk();

    // Schnorr half: Eve signs with her OWN Taproot key, but the indexer will
    // verify against alice_xonly — mismatch.
    let schnorr_msg = {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(&eve_bls_pk.to_bytes());
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        Message::from_digest_slice(&digest).expect("32-byte digest")
    };
    let eve_schnorr_sig = secp.sign_schnorr(&schnorr_msg, &eve_keypair).serialize();

    // BLS half: Eve CAN produce this — she signs alice_xonly with eve_bls_sk.
    let bls_binding_msg = {
        let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + 32);
        msg.extend_from_slice(BLS_BINDING_PREFIX);
        msg.extend_from_slice(&alice_xonly.serialize());
        msg
    };
    let eve_bls_binding_sig = eve_bls_sk
        .sign(&bls_binding_msg, KONTOR_BLS_DST, &[])
        .to_bytes();

    // Attempt the old bundled registration attack in the new aggregate envelope.
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

/// Valid Schnorr, forged BLS binding: Eve controls her Taproot key so she can
/// produce a valid Schnorr signature over `SCHNORR_BINDING_PREFIX || bls_pk`,
/// but submits a BLS binding proof signed by a *different* BLS key than the one
/// being registered. The indexer must reject registration even though the
/// Schnorr half passes.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_attack_valid_schnorr_forged_bls_binding_regtest() -> Result<()> {
    let mut eve = reg_tester.unregistered_identity().await?;

    let eve_bls_sk = BlsSecretKey::from_bytes(&eve.bls_secret_key).unwrap();
    let eve_bls_pk = eve_bls_sk.sk_to_pk();

    // A second, unrelated BLS key that Eve also controls.
    let mut alt_ikm = [0u8; 32];
    alt_ikm[0] = 0xAB;
    let alt_bls_sk = BlsSecretKey::key_gen(&alt_ikm, &[]).expect("alt key_gen");

    // Schnorr half: valid — Eve signs over her real BLS pubkey with her
    // Taproot key. This will pass verification.
    let secp = Secp256k1::new();
    let schnorr_msg = {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(&eve_bls_pk.to_bytes());
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        Message::from_digest_slice(&digest).expect("32-byte digest")
    };
    let schnorr_sig = secp.sign_schnorr(&schnorr_msg, &eve.keypair).serialize();

    // BLS half: forged — signed with alt_bls_sk instead of eve_bls_sk.
    // The binding message is correct (`BLS_BINDING_PREFIX || eve_xonly`), but
    // it was signed by the wrong key. Verification against eve_bls_pk fails:
    // e(alt_sk·H(msg), G2) ≠ e(H(msg), eve_bls_pk).
    let bls_binding_msg = {
        let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + 32);
        msg.extend_from_slice(BLS_BINDING_PREFIX);
        msg.extend_from_slice(&eve.keypair.x_only_public_key().0.serialize());
        msg
    };
    let forged_bls_sig = alt_bls_sk
        .sign(&bls_binding_msg, KONTOR_BLS_DST, &[])
        .to_bytes();

    let _ = reg_tester
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
