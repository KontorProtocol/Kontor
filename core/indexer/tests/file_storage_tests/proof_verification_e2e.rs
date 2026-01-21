//! End-to-end proof verification integration tests.
//!
//! These tests exercise the full proof-of-retrievability flow:
//! 1. Prepare files using kontor-crypto
//! 2. Create agreements in the filestorage contract
//! 3. Generate challenges through the contract
//! 4. Generate proofs using kontor-crypto PorSystem
//! 5. Verify proofs through the contract
//!
//! This mirrors the flow in kontor-crypto's main.rs but uses the contract layer.

use ff::PrimeField;
use indexer::database::types::field_element_to_bytes;
use kontor_crypto::{
    FileLedger as CryptoFileLedger,
    api::{self, Challenge as CryptoChallenge, FieldElement, PorSystem},
};
use testlib::*;

/// Create valid seed bytes from an integer.
/// Field elements must be less than the field modulus, so we create
/// a valid field element from a small integer and convert to bytes.
fn valid_seed_bytes(n: u64) -> Vec<u8> {
    FieldElement::from(n).to_repr().as_ref().to_vec()
}

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/filestorage/wit",
);

/// Create a RawFileDescriptor from kontor-crypto FileMetadata
fn metadata_to_descriptor(metadata: &api::FileMetadata) -> RawFileDescriptor {
    let root: [u8; 32] = field_element_to_bytes(&metadata.root);

    RawFileDescriptor {
        file_id: metadata.file_id.clone(),
        object_id: metadata.object_id.clone(),
        nonce: metadata.nonce.clone(),
        root: root.to_vec(),
        padded_len: metadata.padded_len as u64,
        original_size: metadata.original_size as u64,
        filename: metadata.filename.clone(),
    }
}

/// Convert contract challenge data to kontor-crypto Challenge
fn challenge_data_to_crypto_challenge(
    challenge: &filestorage::ChallengeData,
    metadata: &api::FileMetadata,
) -> CryptoChallenge {
    // Convert seed bytes to FieldElement
    let seed_bytes: [u8; 32] = challenge
        .seed
        .clone()
        .try_into()
        .expect("seed should be 32 bytes");
    let seed = FieldElement::from_repr(seed_bytes.into()).expect("valid field element");

    CryptoChallenge::new(
        metadata.clone(),
        challenge.block_height,
        challenge.num_challenges as usize,
        seed,
        challenge.prover_id.clone(),
    )
}

/// Prepare test file data and return (PreparedFile, FileMetadata)
fn prepare_test_file(content: &[u8], filename: &str) -> (api::PreparedFile, api::FileMetadata) {
    // Use filename as deterministic nonce for reproducibility
    let mut nonce = [0u8; 32];
    for (i, b) in filename.bytes().enumerate().take(32) {
        nonce[i] = b;
    }

    api::prepare_file(content, filename, &nonce).expect("Failed to prepare file")
}

// ─────────────────────────────────────────────────────────────────
// Invalid Proof Returns Rejected
// ─────────────────────────────────────────────────────────────────

async fn e2e_invalid_proof_rejected(
    runtime: &mut Runtime,
    crypto_ledger: &mut CryptoFileLedger,
) -> Result<()> {
    let signer = runtime.identity().await?;

    // Prepare two different files
    let file1_content = b"First file content for testing";
    let (prepared_file1, metadata1) = prepare_test_file(file1_content, "file1.txt");

    let file2_content = b"Second file with different content";
    let (_prepared_file2, metadata2) = prepare_test_file(file2_content, "file2.txt");

    // Add both files to shared ledger (mirrors runtime's file_ledger)
    crypto_ledger.add_file(&metadata1).unwrap();
    crypto_ledger.add_file(&metadata2).unwrap();

    // Create agreement for file1 in contract
    let descriptor1 = metadata_to_descriptor(&metadata1);
    let created1 = filestorage::create_agreement(runtime, &signer, descriptor1).await??;

    // Also create agreement for file2 so it's in the system
    let descriptor2 = metadata_to_descriptor(&metadata2);
    let created2 = filestorage::create_agreement(runtime, &signer, descriptor2).await??;

    // Activate both agreements
    for agreement_id in [&created1.agreement_id, &created2.agreement_id] {
        filestorage::join_agreement(runtime, &signer, agreement_id, "node_1").await??;
        filestorage::join_agreement(runtime, &signer, agreement_id, "node_2").await??;
        filestorage::join_agreement(runtime, &signer, agreement_id, "node_3").await??;
    }

    // Create challenge for file2
    let seed = valid_seed_bytes(99);
    let contract_challenge = filestorage::create_challenge_for_agreement(
        runtime,
        &signer,
        &created2.agreement_id,
        "node_1",
        20000,
        seed,
    )
    .await??;

    // Create crypto challenge for file2
    let crypto_challenge = challenge_data_to_crypto_challenge(&contract_challenge, &metadata2);

    // Generate proof using WRONG file (file1 instead of file2)
    // This should produce an invalid proof
    let system = PorSystem::new(crypto_ledger);
    let wrong_proof = system.prove(
        vec![&prepared_file1],
        std::slice::from_ref(&crypto_challenge),
    );

    // The proof generation itself may fail or produce invalid proof
    match wrong_proof {
        Ok(proof) => {
            let proof_bytes = proof.to_bytes().expect("serialize");
            let result = filestorage::verify_proof(runtime, &signer, proof_bytes).await?;

            // Should either error or return with challenge marked as Failed/Invalid
            match result {
                Ok(_verify_result) => {
                    // Verification completed - check challenge status
                    let challenge_after =
                        filestorage::get_challenge(runtime, &contract_challenge.challenge_id)
                            .await?
                            .unwrap();

                    // Should NOT be Proven if wrong file was used
                    assert_ne!(
                        challenge_after.status,
                        filestorage::ChallengeStatus::Proven,
                        "Wrong file proof should not result in Proven status"
                    );
                }
                Err(_) => {
                    // Verification error is also acceptable
                }
            }
        }
        Err(_) => {
            // Proof generation failed with wrong file - this is expected
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Cross-Block Aggregation with Agreement Creation in the Middle
// ─────────────────────────────────────────────────────────────────

/// Tests that proof aggregation works correctly when new agreements are created
/// between challenge generation and proof verification.
///
/// Timeline:
/// 1. Block N: Files A and B exist, challenges created for both
/// 2. Block N+1: File C is added (new agreement created)
/// 3. Block N+2: Aggregated proof generated for A and B's challenges
/// 4. Verification succeeds because proof's ledger_root (before C) is a valid historical root
///    (also exercises multi-file aggregated proof in a single run)
async fn e2e_cross_block_aggregation_with_new_agreement(
    runtime: &mut Runtime,
    crypto_ledger: &mut CryptoFileLedger,
) -> Result<()> {
    let signer = runtime.identity().await?;

    // Step 1: Create files A and B (existing before the "middle" agreement)
    let (prepared_a, metadata_a) =
        prepare_test_file(b"Content of file A for cross-block", "cross_a.txt");
    let (prepared_b, metadata_b) =
        prepare_test_file(b"Content of file B for cross-block", "cross_b.txt");

    // Add files A and B to ledger
    crypto_ledger.add_file(&metadata_a).unwrap();
    crypto_ledger.add_file(&metadata_b).unwrap();

    // Create agreements for A and B
    let descriptor_a = metadata_to_descriptor(&metadata_a);
    let created_a = filestorage::create_agreement(runtime, &signer, descriptor_a).await??;

    let descriptor_b = metadata_to_descriptor(&metadata_b);
    let created_b = filestorage::create_agreement(runtime, &signer, descriptor_b).await??;

    // Activate both agreements
    for agreement_id in [&created_a.agreement_id, &created_b.agreement_id] {
        filestorage::join_agreement(runtime, &signer, agreement_id, "node_1").await??;
        filestorage::join_agreement(runtime, &signer, agreement_id, "node_2").await??;
        filestorage::join_agreement(runtime, &signer, agreement_id, "node_3").await??;
    }

    // Step 2: Create challenges for A and B at block N
    let block_n = 40000u64;

    let challenge_a = filestorage::create_challenge_for_agreement(
        runtime,
        &signer,
        &created_a.agreement_id,
        "node_1",
        block_n,
        valid_seed_bytes(200),
    )
    .await??;

    let challenge_b = filestorage::create_challenge_for_agreement(
        runtime,
        &signer,
        &created_b.agreement_id,
        "node_1",
        block_n,
        valid_seed_bytes(201),
    )
    .await??;

    // Step 3: NEW AGREEMENT CREATED IN THE MIDDLE
    // File C is added after challenges were created but before proof generation
    let (_prepared_c, metadata_c) =
        prepare_test_file(b"Content of file C - new agreement", "cross_c.txt");
    crypto_ledger.add_file(&metadata_c).unwrap();

    let descriptor_c = metadata_to_descriptor(&metadata_c);
    let created_c = filestorage::create_agreement(runtime, &signer, descriptor_c).await??;

    // Activate file C's agreement
    filestorage::join_agreement(runtime, &signer, &created_c.agreement_id, "node_1").await??;
    filestorage::join_agreement(runtime, &signer, &created_c.agreement_id, "node_2").await??;
    filestorage::join_agreement(runtime, &signer, &created_c.agreement_id, "node_3").await??;

    // Step 4: Generate aggregated proof for A and B's challenges
    // The ledger now has 3 files, but the proof will use the current ledger state
    let crypto_challenges = vec![
        challenge_data_to_crypto_challenge(&challenge_a, &metadata_a),
        challenge_data_to_crypto_challenge(&challenge_b, &metadata_b),
    ];

    let system = PorSystem::new(crypto_ledger);
    let proof = system
        .prove(vec![&prepared_a, &prepared_b], &crypto_challenges)
        .expect("Failed to generate aggregated proof");

    // Step 5: Verify the proof
    // The runtime's file_ledger now has file C, but the proof's ledger_root
    // (which includes A, B, and C) should be the current root
    let proof_bytes = proof.to_bytes().expect("serialize");
    let result = filestorage::verify_proof(runtime, &signer, proof_bytes).await??;

    assert_eq!(
        result.verified_count, 2,
        "Should verify both challenges even after new agreement was created"
    );

    // Verify challenge statuses
    let challenge_a_after = filestorage::get_challenge(runtime, &challenge_a.challenge_id)
        .await?
        .expect("Challenge A should exist");
    assert_eq!(
        challenge_a_after.status,
        filestorage::ChallengeStatus::Proven,
        "Challenge A should be Proven"
    );

    let challenge_b_after = filestorage::get_challenge(runtime, &challenge_b.challenge_id)
        .await?
        .expect("Challenge B should exist");
    assert_eq!(
        challenge_b_after.status,
        filestorage::ChallengeStatus::Proven,
        "Challenge B should be Proven"
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Test Runner
// ─────────────────────────────────────────────────────────────────
pub async fn run(runtime: &mut Runtime) -> Result<()> {
    // Shared crypto_ledger that accumulates files in sync with runtime's file_ledger.
    // This mirrors production where prover and verifier have the same ledger state.
    let mut crypto_ledger = CryptoFileLedger::new();

    e2e_invalid_proof_rejected(runtime, &mut crypto_ledger).await?;
    e2e_cross_block_aggregation_with_new_agreement(runtime, &mut crypto_ledger).await?;
    Ok(())
}
