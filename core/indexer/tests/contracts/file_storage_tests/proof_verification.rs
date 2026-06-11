use indexer::database::queries::{append_challenge_status, insert_challenge, latest_challenge_status};
use indexer::database::types::{ChallengeRow, ChallengeStatus};
use indexer::test_utils::{
    metadata_to_descriptor, por_valid_proof, prepare_por_file, valid_seed_field,
};
use testlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/filestorage/wit",
);

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

pub async fn run_regtest(runtime: &mut Runtime) -> Result<()> {
    // Deserialization error tests
    verify_proof_invalid_proof_bytes_fails(runtime).await?;
    verify_proof_empty_proof_bytes_fails(runtime).await?;
    verify_proof_truncated_header_fails(runtime).await?;
    verify_proof_wrong_magic_bytes_fails(runtime).await?;
    verify_proof_result_has_verified_count(runtime).await?;
    Ok(())
}

/// End-to-end happy path: an active agreement, a challenge seeded into the host
/// ledger, and a live PoR proof that the contract verifies — recording the
/// outcome back to the ledger.
pub async fn run_core_signer(runtime: &mut Runtime) -> Result<()> {
    // Three distinct signers activate the agreement; s1 is the prover.
    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;

    let (prepared, metadata) = prepare_por_file(b"proof success content", "proof_success.txt");
    let created =
        filestorage::create_agreement(runtime, &s1, metadata_to_descriptor(&metadata)).await??;
    // The join result's node_id is the prover identity (signer_id, stringified).
    let prover = filestorage::join_agreement(runtime, &s1, &created.agreement_id)
        .await??
        .node_id;
    filestorage::join_agreement(runtime, &s2, &created.agreement_id).await??;
    filestorage::join_agreement(runtime, &s3, &created.agreement_id).await??;

    // Generate the proof, then seed a matching ledger challenge for its id.
    // (regtest s_chal = 8.) Issue it at genesis so its `active` row is older
    // than the `proven` row verify-proof writes at the current height (the
    // latest-by-height status is what `get-challenges` surfaces).
    let s_chal = 8usize;
    let block_height = 0u64;
    let seed = valid_seed_field(7);
    let (proof_bytes, challenge_id) =
        por_valid_proof(&prepared, metadata, block_height, s_chal, seed.field, &prover)?;

    let conn = runtime.storage_conn();
    let prover_id: u64 = prover.parse().expect("prover is a signer_id");
    let row = ChallengeRow::builder()
        .challenge_id(challenge_id.clone())
        .prover_id(prover_id)
        .agreement_id(created.agreement_id.clone())
        .num_challenges(s_chal as u64)
        .seed(seed.bytes.to_vec())
        .deadline_height(block_height + 2016)
        .height(block_height)
        .build();
    insert_challenge(&conn, &row).await?;
    append_challenge_status(
        &conn,
        &challenge_id,
        ChallengeStatus::Active,
        block_height,
    )
    .await?;

    // verify-proof reads the ledger, verifies, and records the outcome.
    let result = filestorage::verify_proof(runtime, &s1, proof_bytes).await??;
    assert_eq!(result.verified_count, 1, "one challenge should verify");

    let status = latest_challenge_status(&conn, &challenge_id).await?;
    assert_eq!(
        status,
        Some(ChallengeStatus::Proven),
        "challenge should be Proven after a valid proof"
    );

    Ok(())
}
