//! End-to-end proof verification integration tests.
//!
//! These tests exercise the full proof-of-retrievability flow:
//! 1. Prepare files using kontor-crypto
//! 2. Create agreements in the filestorage contract
//! 3. Generate challenges through the contract
//! 4. Load precomputed proofs from fixtures
//! 5. Verify proofs through the contract
//!
//! This mirrors the flow in kontor-crypto's main.rs but uses the contract layer.

use ff::PrimeField;
use indexer::database::types::field_element_to_bytes;
use kontor_crypto::api::{self, FieldElement};
use serde::Deserialize;
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

/// Prepare test file data and return (PreparedFile, FileMetadata)
fn prepare_test_file(content: &[u8], filename: &str) -> (api::PreparedFile, api::FileMetadata) {
    // Use filename as deterministic nonce for reproducibility
    let mut nonce = [0u8; 32];
    for (i, b) in filename.bytes().enumerate().take(32) {
        nonce[i] = b;
    }

    api::prepare_file(content, filename, &nonce).expect("Failed to prepare file")
}

#[derive(Debug, Deserialize)]
struct PorProofFixtures {
    invalid_proof_hex: String,
    cross_block_agg_hex: String,
}

fn load_por_fixtures() -> Result<PorProofFixtures> {
    let raw = include_str!("../fixtures/por_proof_fixtures.json");
    let fixtures: PorProofFixtures =
        serde_json::from_str(raw).map_err(|e| anyhow!("Invalid fixtures JSON: {e}"))?;
    Ok(fixtures)
}

fn decode_fixture_hex(field: &str, value: &str) -> Result<Vec<u8>> {
    if value.trim().is_empty() {
        return Err(anyhow!(
            "Fixture value for {field} is empty. Run: cargo run --bin generate_por_fixtures"
        ));
    }
    hex::decode(value.trim()).map_err(|e| anyhow!("Invalid hex for {field}: {e}"))
}

// ─────────────────────────────────────────────────────────────────
// Invalid Proof Returns Rejected
// ─────────────────────────────────────────────────────────────────

async fn e2e_invalid_proof_rejected(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let fixtures = load_por_fixtures()?;

    // Prepare file
    let file2_content = b"Second file with different content";
    let (_prepared_file2, metadata2) = prepare_test_file(file2_content, "file2.txt");

    // Create agreement for file2 in contract
    let descriptor2 = metadata_to_descriptor(&metadata2);
    let created2 = filestorage::create_agreement(runtime, &signer, descriptor2).await??;

    // Activate agreement
    filestorage::join_agreement(runtime, &signer, &created2.agreement_id, "node_1").await??;
    filestorage::join_agreement(runtime, &signer, &created2.agreement_id, "node_2").await??;
    filestorage::join_agreement(runtime, &signer, &created2.agreement_id, "node_3").await??;

    let proof_bytes = decode_fixture_hex("invalid_proof_hex", &fixtures.invalid_proof_hex)?;
    let result = filestorage::verify_proof(runtime, &signer, proof_bytes).await?;
    assert!(result.is_err(), "Invalid proof should be rejected");

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
async fn e2e_cross_block_aggregation_with_new_agreement(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let fixtures = load_por_fixtures()?;

    // Step 1: Create files A and B (existing before the "middle" agreement)
    let (_prepared_a, metadata_a) =
        prepare_test_file(b"Content of file A for cross-block", "cross_a.txt");
    let (_prepared_b, metadata_b) =
        prepare_test_file(b"Content of file B for cross-block", "cross_b.txt");

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

    let descriptor_c = metadata_to_descriptor(&metadata_c);
    let created_c = filestorage::create_agreement(runtime, &signer, descriptor_c).await??;

    // Activate file C's agreement
    filestorage::join_agreement(runtime, &signer, &created_c.agreement_id, "node_1").await??;
    filestorage::join_agreement(runtime, &signer, &created_c.agreement_id, "node_2").await??;
    filestorage::join_agreement(runtime, &signer, &created_c.agreement_id, "node_3").await??;

    // Step 4: Verify the precomputed proof
    let proof_bytes = decode_fixture_hex("cross_block_agg_hex", &fixtures.cross_block_agg_hex)?;
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
    e2e_cross_block_aggregation_with_new_agreement(runtime).await?;
    e2e_invalid_proof_rejected(runtime).await?;
    Ok(())
}
