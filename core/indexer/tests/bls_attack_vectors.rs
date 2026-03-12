//! BLS attack vector tests.
//!
//! Tests that verify the Kontor BLS registration and aggregation scheme
//! is resistant to known attacks:
//! - Rogue-key attacks (Boneh, Drijvers, Neven 2018; <https://eprint.iacr.org/2018/483>)
//! - Proof replay across identities
//! - Aggregate-level forgery with same vs distinct messages

use anyhow::{Result, anyhow};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::rand::RngCore;
use bitcoin::key::{Secp256k1, rand};
use bitcoin::secp256k1::Message;
use bitcoin::{Address, Network};
use blst::BLST_ERROR;
use blst::min_sig::AggregateSignature;
use blst::min_sig::SecretKey as BlsSecretKey;
use indexer::bls::{
    BLS_BINDING_PREFIX, KONTOR_BLS_DST, RegistrationProof, SCHNORR_BINDING_PREFIX,
    bls_derivation_path, derive_bls_secret_key_eip2333, taproot_derivation_path,
};
use indexer::reg_tester::{Identity, RegTester, derive_taproot_keypair_from_seed};
use indexer_types::Inst;
use testlib::{
    AnyhowError, ContractAddress, Decimal, Error, Integer, RawFileDescriptor, Runtime,
    RuntimeConfig, Signer, import, serial_test,
};

import!(
    name = "registry",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    unsafe {
        // Decompress 96-byte compressed G2 points → affine → projective
        let mut beta_aff = blst::blst_p2_affine::default();
        let mut victim_aff = blst::blst_p2_affine::default();
        blst::blst_p2_uncompress(&mut beta_aff, beta_pk_compressed.as_ptr());
        blst::blst_p2_uncompress(&mut victim_aff, victim_pk_compressed.as_ptr());

        let mut beta_proj = blst::blst_p2::default();
        let mut victim_proj = blst::blst_p2::default();
        blst::blst_p2_from_affine(&mut beta_proj, &beta_aff);
        blst::blst_p2_from_affine(&mut victim_proj, &victim_aff);

        // -PK_victim
        blst::blst_p2_cneg(&mut victim_proj, true);

        // PK_rogue = β·G2 + (-PK_victim)
        let mut rogue_proj = blst::blst_p2::default();
        blst::blst_p2_add_or_double(&mut rogue_proj, &beta_proj, &victim_proj);

        // Back to compressed 96-byte form
        let mut rogue_aff = blst::blst_p2_affine::default();
        blst::blst_p2_to_affine(&mut rogue_aff, &rogue_proj);

        let mut out = [0u8; 96];
        blst::blst_p2_affine_compress(out.as_mut_ptr(), &rogue_aff);
        out
    }
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
    let mut victim = unregistered_identity(&mut reg_tester).await?;
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

    let mut attacker = unregistered_identity(&mut reg_tester).await?;
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
        registry::get_signer_id(runtime, &attacker_xonly).await?,
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
    let mut alice = unregistered_identity(&mut reg_tester).await?;
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
    assert_eq!(
        registry::get_signer_id(runtime, &alice_xonly).await?,
        Some(0)
    );

    // Eve creates her own Schnorr binding to Alice's BLS pubkey (she controls
    // her Taproot key, so this is trivial).
    let mut eve = unregistered_identity(&mut reg_tester).await?;
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
        registry::get_signer_id(runtime, &eve_xonly).await?,
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
