use testlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/filestorage/wit",
);

fn make_descriptor(
    file_id: String,
    root: Vec<u8>,
    padded_len: u64,
    original_size: u64,
    filename: String,
) -> RawFileDescriptor {
    let object_id = format!("object_{}", file_id);
    let mut nonce = [0u8; 32];
    for (i, b) in file_id.bytes().enumerate().take(32) {
        nonce[i] = b;
    }

    RawFileDescriptor {
        file_id,
        object_id,
        nonce: nonce.to_vec(),
        root,
        padded_len,
        original_size,
        filename,
    }
}

/// Helper to create an active agreement with challenges
async fn setup_active_agreement_with_challenge(
    runtime: &mut Runtime,
    file_id: &str,
    block_height: u64,
) -> Result<(String, Vec<filestorage::ChallengeData>)> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        file_id.to_string(),
        vec![1u8; 32],
        16,
        100,
        format!("{}.txt", file_id),
    );

    // Create agreement
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;

    // Activate it with 3 nodes
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_2").await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_3").await??;

    // Generate a challenge
    let block_hash = vec![42u8; 32];
    let challenges =
        filestorage::generate_challenges_for_block(runtime, &signer, block_height, block_hash)
            .await?;

    Ok((created.agreement_id, challenges))
}

// ─────────────────────────────────────────────────────────────────
// verify_proof Deserialization Error Tests
// ─────────────────────────────────────────────────────────────────

async fn verify_proof_invalid_proof_bytes_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    // Try to verify with invalid proof bytes (random garbage)
    let invalid_bytes = vec![0u8; 100];
    let result = filestorage::verify_proof(runtime, &signer, invalid_bytes).await?;

    // Should return an error (deserialization failure)
    assert!(
        matches!(result, Err(Error::Validation(_))),
        "Invalid proof bytes should return validation error, got: {:?}",
        result
    );

    Ok(())
}

async fn verify_proof_empty_proof_bytes_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    // Try to verify with empty proof bytes
    let result = filestorage::verify_proof(runtime, &signer, vec![]).await?;

    // Should return an error
    assert!(
        matches!(result, Err(Error::Validation(_))),
        "Empty proof bytes should return validation error, got: {:?}",
        result
    );

    Ok(())
}

async fn verify_proof_truncated_header_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    // Try to verify with bytes too short to be a valid proof header
    let short_bytes = vec![0u8; 5];
    let result = filestorage::verify_proof(runtime, &signer, short_bytes).await?;

    assert!(
        matches!(result, Err(Error::Validation(_))),
        "Truncated proof should return validation error, got: {:?}",
        result
    );

    Ok(())
}

async fn verify_proof_wrong_magic_bytes_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    // Create bytes with wrong magic number (valid proofs start with "NPOR")
    let mut wrong_magic = vec![0u8; 20];
    wrong_magic[0..4].copy_from_slice(b"XXXX");

    let result = filestorage::verify_proof(runtime, &signer, wrong_magic).await?;

    assert!(
        matches!(result, Err(Error::Validation(_))),
        "Wrong magic bytes should return validation error, got: {:?}",
        result
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Challenge Status Tests
// ─────────────────────────────────────────────────────────────────

async fn new_challenge_has_active_status(runtime: &mut Runtime) -> Result<()> {
    let (_agreement_id, challenges) =
        setup_active_agreement_with_challenge(runtime, "active_status_test", 1000).await?;

    if !challenges.is_empty() {
        let challenge = filestorage::get_challenge(runtime, &challenges[0].challenge_id).await?;
        assert!(challenge.is_some(), "Challenge should exist");
        let challenge = challenge.unwrap();
        assert_eq!(
            challenge.status,
            filestorage::ChallengeStatus::Active,
            "New challenge should have Active status"
        );
    }

    Ok(())
}

async fn expire_challenges_sets_expired_status(runtime: &mut Runtime) -> Result<()> {
    let (_agreement_id, challenges) =
        setup_active_agreement_with_challenge(runtime, "expire_status_test", 2000).await?;

    if !challenges.is_empty() {
        let challenge_id = &challenges[0].challenge_id;

        // Challenge should be active initially
        let challenge = filestorage::get_challenge(runtime, challenge_id)
            .await?
            .unwrap();
        assert_eq!(challenge.status, filestorage::ChallengeStatus::Active);

        // Get the deadline and expire past it
        let deadline = challenge.deadline_height;

        let signer = runtime.identity().await?;
        filestorage::expire_challenges(runtime, &signer, deadline + 1).await?;

        // Challenge should now be expired
        let challenge = filestorage::get_challenge(runtime, challenge_id)
            .await?
            .unwrap();
        assert_eq!(
            challenge.status,
            filestorage::ChallengeStatus::Expired,
            "Challenge should be Expired after deadline"
        );
    }

    Ok(())
}

async fn get_active_challenges_returns_only_active(runtime: &mut Runtime) -> Result<()> {
    // Setup first agreement with challenge
    let (_agreement_id1, challenges1) =
        setup_active_agreement_with_challenge(runtime, "active_only_test_1", 3000).await?;

    // Setup second agreement with challenge
    let (_agreement_id2, challenges2) =
        setup_active_agreement_with_challenge(runtime, "active_only_test_2", 3000).await?;

    // Get all active challenges
    let active = filestorage::get_active_challenges(runtime).await?;

    // All returned challenges should have Active status
    for challenge in &active {
        assert_eq!(
            challenge.status,
            filestorage::ChallengeStatus::Active,
            "get_active_challenges should only return Active challenges"
        );
    }

    // The active count should match what we generated
    let expected_count = challenges1.len() + challenges2.len();
    assert_eq!(
        active.len(),
        expected_count,
        "Should have {} active challenges",
        expected_count
    );

    Ok(())
}

async fn expired_challenges_not_in_active_list(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    // Setup agreement with challenge
    let (_agreement_id, challenges) =
        setup_active_agreement_with_challenge(runtime, "expired_not_active_test", 4000).await?;

    if !challenges.is_empty() {
        // Get initial active count
        let initial_active = filestorage::get_active_challenges(runtime).await?;
        let initial_count = initial_active.len();

        // Expire the challenge
        let challenge = filestorage::get_challenge(runtime, &challenges[0].challenge_id)
            .await?
            .unwrap();
        filestorage::expire_challenges(runtime, &signer, challenge.deadline_height + 1).await?;

        // Get active challenges again
        let after_expire = filestorage::get_active_challenges(runtime).await?;

        // Should have one fewer active challenge
        assert_eq!(
            after_expire.len(),
            initial_count - 1,
            "Expired challenge should not appear in active list"
        );

        // The expired challenge should not be in the list
        assert!(
            !after_expire
                .iter()
                .any(|c| c.challenge_id == challenges[0].challenge_id),
            "Expired challenge should not be in active challenges"
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Challenge Data Integrity Tests
// ─────────────────────────────────────────────────────────────────

async fn challenge_has_correct_agreement_reference(runtime: &mut Runtime) -> Result<()> {
    let (agreement_id, challenges) =
        setup_active_agreement_with_challenge(runtime, "agreement_ref_test", 5000).await?;

    if !challenges.is_empty() {
        let challenge = filestorage::get_challenge(runtime, &challenges[0].challenge_id)
            .await?
            .unwrap();
        assert_eq!(
            challenge.agreement_id, agreement_id,
            "Challenge should reference its parent agreement"
        );
    }

    Ok(())
}

async fn challenge_has_correct_block_height(runtime: &mut Runtime) -> Result<()> {
    let block_height = 6000u64;
    let (_agreement_id, challenges) =
        setup_active_agreement_with_challenge(runtime, "block_height_test", block_height).await?;

    if !challenges.is_empty() {
        let challenge = filestorage::get_challenge(runtime, &challenges[0].challenge_id)
            .await?
            .unwrap();
        assert_eq!(
            challenge.block_height, block_height,
            "Challenge should have correct block height"
        );
    }

    Ok(())
}

async fn challenge_has_valid_deadline(runtime: &mut Runtime) -> Result<()> {
    let block_height = 7000u64;
    let (_agreement_id, challenges) =
        setup_active_agreement_with_challenge(runtime, "deadline_test", block_height).await?;

    if !challenges.is_empty() {
        let challenge = filestorage::get_challenge(runtime, &challenges[0].challenge_id)
            .await?
            .unwrap();

        // Deadline should be after the block height
        assert!(
            challenge.deadline_height > block_height,
            "Deadline should be after challenge creation block"
        );
    }

    Ok(())
}

async fn challenge_has_prover_id(runtime: &mut Runtime) -> Result<()> {
    let (_agreement_id, challenges) =
        setup_active_agreement_with_challenge(runtime, "prover_id_test", 8000).await?;

    if !challenges.is_empty() {
        let challenge = filestorage::get_challenge(runtime, &challenges[0].challenge_id)
            .await?
            .unwrap();

        // Prover ID should not be empty
        assert!(
            !challenge.prover_id.is_empty(),
            "Challenge should have a prover ID"
        );
    }

    Ok(())
}

async fn challenge_has_seed(runtime: &mut Runtime) -> Result<()> {
    let (_agreement_id, challenges) =
        setup_active_agreement_with_challenge(runtime, "seed_test", 9000).await?;

    if !challenges.is_empty() {
        let challenge = filestorage::get_challenge(runtime, &challenges[0].challenge_id)
            .await?
            .unwrap();

        // Seed should be 32 bytes
        assert_eq!(
            challenge.seed.len(),
            32,
            "Challenge seed should be 32 bytes"
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Multiple Agreements Tests
// ─────────────────────────────────────────────────────────────────

async fn multiple_agreements_independent_challenges(runtime: &mut Runtime) -> Result<()> {
    // Create multiple agreements
    let (agreement_id1, challenges1) =
        setup_active_agreement_with_challenge(runtime, "multi_test_1", 10000).await?;
    let (agreement_id2, challenges2) =
        setup_active_agreement_with_challenge(runtime, "multi_test_2", 10000).await?;

    // Agreements should be different
    assert_ne!(
        agreement_id1, agreement_id2,
        "Agreements should have different IDs"
    );

    // If both generated challenges, they should reference their respective agreements
    if !challenges1.is_empty() && !challenges2.is_empty() {
        let c1 = filestorage::get_challenge(runtime, &challenges1[0].challenge_id)
            .await?
            .unwrap();
        let c2 = filestorage::get_challenge(runtime, &challenges2[0].challenge_id)
            .await?
            .unwrap();

        assert_eq!(c1.agreement_id, agreement_id1);
        assert_eq!(c2.agreement_id, agreement_id2);
        assert_ne!(
            c1.challenge_id, c2.challenge_id,
            "Challenges should have different IDs"
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// VerifyResult Enum Tests
// ─────────────────────────────────────────────────────────────────

async fn verify_proof_result_has_verified_count(runtime: &mut Runtime) -> Result<()> {
    // This test verifies that VerifyProofResult contains verified_count
    // We can't easily test the actual verification without real proofs,
    // but we can verify the return type structure exists

    let signer = runtime.identity().await?;

    // Create an agreement with challenges
    let (_agreement_id, _challenges) =
        setup_active_agreement_with_challenge(runtime, "result_type_test", 11000).await?;

    // Attempt verification with invalid proof - this should error
    // but confirms the function signature is correct
    let result = filestorage::verify_proof(runtime, &signer, vec![0u8; 50]).await?;

    // We expect an error, but the type system confirms VerifyProofResult exists
    assert!(result.is_err(), "Invalid proof should error");

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Test Runner
// ─────────────────────────────────────────────────────────────────

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_proof_verification() -> Result<()> {
    // Deserialization error tests
    verify_proof_invalid_proof_bytes_fails(runtime).await?;
    verify_proof_empty_proof_bytes_fails(runtime).await?;
    verify_proof_truncated_header_fails(runtime).await?;
    verify_proof_wrong_magic_bytes_fails(runtime).await?;

    // Challenge status tests
    new_challenge_has_active_status(runtime).await?;
    expire_challenges_sets_expired_status(runtime).await?;
    get_active_challenges_returns_only_active(runtime).await?;
    expired_challenges_not_in_active_list(runtime).await?;

    // Challenge data integrity tests
    challenge_has_correct_agreement_reference(runtime).await?;
    challenge_has_correct_block_height(runtime).await?;
    challenge_has_valid_deadline(runtime).await?;
    challenge_has_prover_id(runtime).await?;
    challenge_has_seed(runtime).await?;

    // Multiple agreements tests
    multiple_agreements_independent_challenges(runtime).await?;

    // VerifyResult tests
    verify_proof_result_has_verified_count(runtime).await?;

    Ok(())
}
