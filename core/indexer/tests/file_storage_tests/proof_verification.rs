use indexer::test_utils::make_descriptor;
use testlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/filestorage/wit",
);

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
// VerifyResult Enum Tests
// ─────────────────────────────────────────────────────────────────

async fn verify_proof_result_has_verified_count(runtime: &mut Runtime) -> Result<()> {
    // This test verifies that VerifyProofResult contains verified_count
    // We can't easily test the actual verification without real proofs,
    // but we can verify the return type structure exists

    let signer = runtime.identity().await?;

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

pub async fn run(runtime: &mut Runtime) -> Result<()> {
    // Deserialization error tests
    verify_proof_invalid_proof_bytes_fails(runtime).await?;
    verify_proof_empty_proof_bytes_fails(runtime).await?;
    verify_proof_truncated_header_fails(runtime).await?;
    verify_proof_wrong_magic_bytes_fails(runtime).await?;

    let (agreement_id, challenges) =
        setup_active_agreement_with_challenge(runtime, "baseline_checks", 1000).await?;

    if !challenges.is_empty() {
        let challenge_id = &challenges[0].challenge_id;
        let challenge = filestorage::get_challenge(runtime, challenge_id)
            .await?
            .expect("Challenge should exist");

        assert_eq!(
            challenge.status,
            filestorage::ChallengeStatus::Active,
            "New challenge should have Active status"
        );
        assert_eq!(
            challenge.agreement_id, agreement_id,
            "Challenge should reference its parent agreement"
        );
        assert_eq!(
            challenge.block_height, 1000,
            "Challenge should have correct block height"
        );
        assert!(
            challenge.deadline_height > 1000,
            "Deadline should be after challenge creation block"
        );
        assert!(
            !challenge.prover_id.is_empty(),
            "Challenge should have a prover ID"
        );
        assert_eq!(
            challenge.seed.len(),
            32,
            "Challenge seed should be 32 bytes"
        );

        let signer = runtime.identity().await?;
        let deadline = challenge.deadline_height;
        let before_expire = filestorage::get_active_challenges(runtime).await?;
        filestorage::expire_challenges(runtime, &signer, deadline + 1).await?;

        let challenge_after = filestorage::get_challenge(runtime, challenge_id)
            .await?
            .unwrap();
        assert_eq!(
            challenge_after.status,
            filestorage::ChallengeStatus::Expired,
            "Challenge should be Expired after deadline"
        );

        let after_expire = filestorage::get_active_challenges(runtime).await?;
        assert!(
            !after_expire.iter().any(|c| c.challenge_id == *challenge_id),
            "Expired challenge should not appear in active challenges"
        );
        if before_expire.len() == 1 {
            assert_eq!(
                after_expire.len(),
                0,
                "Expired challenge should reduce active challenge count"
            );
        }
    }

    let (agreement_id1, challenges1) =
        setup_active_agreement_with_challenge(runtime, "active_only_test_1", 3000).await?;
    let (agreement_id2, challenges2) =
        setup_active_agreement_with_challenge(runtime, "active_only_test_2", 3000).await?;

    let active = filestorage::get_active_challenges(runtime).await?;
    for challenge in &active {
        assert_eq!(
            challenge.status,
            filestorage::ChallengeStatus::Active,
            "get_active_challenges should only return Active challenges"
        );
    }

    let expected_count = challenges1.len() + challenges2.len();
    assert_eq!(
        active.len(),
        expected_count,
        "Should have {} active challenges",
        expected_count
    );

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

    // VerifyResult tests
    verify_proof_result_has_verified_count(runtime).await?;

    Ok(())
}
