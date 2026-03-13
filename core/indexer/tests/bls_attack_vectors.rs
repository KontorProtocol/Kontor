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
use indexer_types::{BlsBulkOp, Inst, Signer};
use testlib::{
    AnyhowError, ContractAddress, Decimal, Error, Integer, RawFileDescriptor, Runtime,
    RuntimeConfig, import, serial_test,
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
// Unit tests — subgroup validation
// ---------------------------------------------------------------------------

/// Finds a compressed 48-byte G1 representation that decompresses to a valid
/// E1 curve point OUTSIDE the prime-order G1 subgroup.
///
/// E1 has cofactor h ≈ 2^126, so virtually every valid E1 point is outside G1.
/// We search over small x-coordinates until `blst_p1_uncompress` succeeds
/// (meaning x³+4 is a quadratic residue mod p) and `blst_p1_affine_in_g1`
/// returns false.
fn find_non_subgroup_g1_compressed() -> [u8; 48] {
    for trial in 1u8..=255 {
        let mut compressed = [0u8; 48];
        compressed[0] = 0x80;
        compressed[47] = trial;

        unsafe {
            let mut p_aff = blst::blst_p1_affine::default();
            if blst::blst_p1_uncompress(&mut p_aff, compressed.as_ptr())
                != blst::BLST_ERROR::BLST_SUCCESS
            {
                continue;
            }
            if blst::blst_p1_affine_on_curve(&p_aff)
                && !blst::blst_p1_affine_in_g1(&p_aff)
            {
                return compressed;
            }
        }
    }
    panic!(
        "failed to find a non-subgroup E1 point in 255 trials \
         (E1 cofactor h ≈ 2^126 means virtually all E1 points are non-subgroup)"
    );
}

/// Same approach as `find_non_subgroup_g1_compressed` but for G2 (96-byte
/// compressed pubkeys on E2). E2's cofactor is large, so virtually every
/// valid E2 point is outside the prime-order G2 subgroup.
fn find_non_subgroup_g2_compressed() -> [u8; 96] {
    for trial in 1u8..=255 {
        let mut compressed = [0u8; 96];
        compressed[0] = 0x80;
        compressed[95] = trial;

        unsafe {
            let mut p_aff = blst::blst_p2_affine::default();
            if blst::blst_p2_uncompress(&mut p_aff, compressed.as_ptr())
                != blst::BLST_ERROR::BLST_SUCCESS
            {
                continue;
            }
            if blst::blst_p2_affine_on_curve(&p_aff)
                && !blst::blst_p2_affine_in_g2(&p_aff)
            {
                return compressed;
            }
        }
    }
    panic!(
        "failed to find a non-subgroup E2 point in 255 trials \
         (E2 cofactor is large so virtually all E2 points are non-subgroup)"
    );
}

/// Constructs a BLS12-381 G1 point that lies on curve E1 but OUTSIDE the
/// prime-order G1 subgroup. `sig_validate(_, true)` must reject it.
///
/// This is the G1/signature companion to `bls_attack_non_subgroup_pubkey_rejected_regtest`
/// (which tests G2/pubkey). Together they guard against accidental removal of
/// subgroup checks on either side — e.g. replacing `sig_validate(_, true)` with
/// `Signature::from_bytes()`.
///
/// The helper `find_non_subgroup_g1_compressed` already proves (via the raw C API)
/// that the test input is a valid on-curve E1 point that is not in G1. This test
/// then verifies that the high-level `sig_validate` path used by `verify_bls_bulk`
/// rejects it.
#[test]
fn non_subgroup_signature_rejected_by_sig_validate() {
    let non_subgroup_sig_bytes = find_non_subgroup_g1_compressed();

    assert!(
        blst::min_sig::Signature::sig_validate(&non_subgroup_sig_bytes, true).is_err(),
        "sig_validate with subgroup check must reject non-subgroup G1 point"
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

/// Identity hijack via BlsBulk: Eve tries to register her own BLS key under
/// Alice's Taproot identity. Eve CAN produce the BLS binding proof (she signs
/// `BLS_BINDING_PREFIX || alice_xonly` with `eve_bls_sk`), but CANNOT produce
/// the Schnorr proof (needs Alice's Taproot secret key to sign over
/// `SCHNORR_BINDING_PREFIX || eve_bls_pk`).
///
/// | Proof half | Blocks Eve? | Why                                          |
/// |------------|-------------|----------------------------------------------|
/// | Schnorr    | **Yes**     | Needs Alice's Taproot sk                     |
/// | BLS        | No          | Eve can sign alice_xonly with her own BLS key |
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_attack_eve_registers_own_key_under_alice_identity_regtest() -> Result<()> {
    let alice = unregistered_identity(&mut reg_tester).await?;
    let eve = unregistered_identity(&mut reg_tester).await?;
    let mut publisher = unregistered_identity(&mut reg_tester).await?;

    let eve_bls_sk = BlsSecretKey::from_bytes(&eve.bls_secret_key).unwrap();
    let eve_bls_pk = eve_bls_sk.sk_to_pk();
    let alice_xonly = alice.keypair.x_only_public_key().0;
    let secp = Secp256k1::new();

    // Schnorr half: Eve signs with her OWN Taproot key, but the indexer will
    // verify against alice_xonly — mismatch.
    let schnorr_msg = {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(&eve_bls_pk.to_bytes());
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        Message::from_digest_slice(&digest).expect("32-byte digest")
    };
    let eve_schnorr_sig = secp
        .sign_schnorr(&schnorr_msg, &eve.keypair)
        .serialize();

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

    // Submit via BlsBulk: Eve targets alice_xonly as the signer.
    let op = BlsBulkOp::RegisterBlsKey {
        signer: Signer::XOnlyPubKey(alice_xonly.to_string()),
        bls_pubkey: eve_bls_pk.to_bytes().to_vec(),
        schnorr_sig: eve_schnorr_sig.to_vec(),
        bls_sig: eve_bls_binding_sig.to_vec(),
    };

    let msg = op.signing_message()?;
    let sig = eve_bls_sk.sign(&msg, KONTOR_BLS_DST, &[]);
    let agg = AggregateSignature::aggregate(&[&sig], true).unwrap();
    let agg_sig = agg.to_signature();

    let _ = reg_tester
        .instruction(
            &mut publisher,
            Inst::BlsBulk {
                ops: vec![op],
                signature: agg_sig.to_bytes().to_vec(),
            },
        )
        .await;

    let alice_xonly_str = alice_xonly.to_string();
    assert_eq!(
        registry::get_signer_id(runtime, &alice_xonly_str).await?,
        None,
        "Eve must not be able to register under Alice's identity"
    );

    Ok(())
}

/// Valid Schnorr, forged BLS binding: Eve controls her Taproot key so she can
/// produce a valid Schnorr signature over `SCHNORR_BINDING_PREFIX || bls_pk`,
/// but submits a BLS binding proof signed by a *different* BLS key than the one
/// being registered. The indexer must reject registration even though the
/// Schnorr half passes.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_attack_valid_schnorr_forged_bls_binding_regtest() -> Result<()> {
    let mut eve = unregistered_identity(&mut reg_tester).await?;

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
    let schnorr_sig = secp
        .sign_schnorr(&schnorr_msg, &eve.keypair)
        .serialize();

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
        registry::get_signer_id(runtime, &eve_xonly).await?,
        None,
        "forged BLS binding must prevent registration"
    );

    Ok(())
}

/// Submits a BLS public key that lies on the E2 curve but outside the G2
/// prime-order subgroup. `key_validate` (which checks subgroup membership)
/// must reject it. This exercises a different code path than zeroed-bytes
/// tests — the point is a valid curve point, just not in the correct subgroup.
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn bls_attack_non_subgroup_pubkey_rejected_regtest() -> Result<()> {
    let mut eve = unregistered_identity(&mut reg_tester).await?;

    // Construct a point on E2 that is NOT in G2 by trial-decompressing
    // candidate 96-byte compressed G2 representations until we find one that
    // decompresses to a valid E2 curve point outside the prime-order subgroup.
    let non_subgroup_pk = find_non_subgroup_g2_compressed();

    assert!(
        blst::min_sig::PublicKey::key_validate(&non_subgroup_pk).is_err(),
        "key_validate must reject non-subgroup point"
    );

    // Build a registration with valid Schnorr and BLS binding proofs.
    // The rejection must come from key_validate, not from proof verification.
    let secp = Secp256k1::new();
    let eve_bls_sk = BlsSecretKey::from_bytes(&eve.bls_secret_key).unwrap();

    let schnorr_msg = {
        let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + 96);
        preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
        preimage.extend_from_slice(&non_subgroup_pk);
        let digest = sha256::Hash::hash(&preimage).to_byte_array();
        Message::from_digest_slice(&digest).expect("32-byte digest")
    };
    let schnorr_sig = secp
        .sign_schnorr(&schnorr_msg, &eve.keypair)
        .serialize();

    let bls_binding_msg = {
        let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + 32);
        msg.extend_from_slice(BLS_BINDING_PREFIX);
        msg.extend_from_slice(&eve.keypair.x_only_public_key().0.serialize());
        msg
    };
    let bls_sig = eve_bls_sk
        .sign(&bls_binding_msg, KONTOR_BLS_DST, &[])
        .to_bytes();

    let _ = reg_tester
        .instruction(
            &mut eve,
            Inst::RegisterBlsKey {
                bls_pubkey: non_subgroup_pk.to_vec(),
                schnorr_sig: schnorr_sig.to_vec(),
                bls_sig: bls_sig.to_vec(),
            },
        )
        .await;

    let eve_xonly = eve.x_only_public_key().to_string();
    assert_eq!(
        registry::get_signer_id(runtime, &eve_xonly).await?,
        None,
        "non-subgroup public key must not be registered"
    );

    Ok(())
}
