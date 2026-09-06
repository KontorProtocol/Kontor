//! End-to-end proof verification integration tests.
//!
//! These tests exercise the full proof-of-retrievability flow:
//! 1. Prepare files using kontor-crypto
//! 2. Create agreements in the filestorage contract
//! 3. Generate challenges through the contract
//! 4. Generate proofs and exercise rejected submissions
//! 5. Verify proofs through the contract
//!
//! This mirrors the flow in kontor-crypto's main.rs but uses the contract layer.

use indexer::database::types::field_element_to_bytes;
use indexer::test_utils::{
    por_cross_block_proof_bytes, por_single_file_proof_bytes, valid_seed_field,
};
use kontor_crypto::api::{self};
use testlib::*;

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

// ─────────────────────────────────────────────────────────────────
// Invalid Proof Returns Rejected
// ─────────────────────────────────────────────────────────────────

async fn e2e_invalid_proof_rejected(runtime: &mut Runtime) -> Result<()> {
    // Prepare file2 + agreement, activated by three distinct signers.
    let file2_content = b"Second file with different content";
    let (_prepared_file2, metadata2) = prepare_test_file(file2_content, "file2.txt");
    let descriptor2 = metadata_to_descriptor(&metadata2);

    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;
    let created2 = filestorage::create_agreement(runtime, &s1, descriptor2).await??;
    let prover = filestorage::join_agreement(runtime, &s1, &created2.agreement_id)
        .await??
        .node_id;
    filestorage::join_agreement(runtime, &s2, &created2.agreement_id).await??;
    filestorage::join_agreement(runtime, &s3, &created2.agreement_id).await??;

    let challenge = filestorage::create_challenge_for_agreement(
        runtime,
        &s1,
        &created2.agreement_id,
        prover,
        20000,
        valid_seed_field(99).bytes.to_vec(),
    )
    .await??;
    let s_chal = filestorage::get_s_chal(runtime).await? as usize;
    let proof_bytes = por_single_file_proof_bytes(prover, s_chal)?;
    let mut invalid_shape = api::Proof::from_bytes(&proof_bytes)?;
    invalid_shape.aggregated_tree_depth = 1;
    let mut rejected = api::Proof::from_bytes(&proof_bytes)?;
    // Single-file proofs bypass the historical-root check. Changing this public
    // input preserves the proof's shape but fails SNARK verification.
    rejected.ledger_root += api::FieldElement::from(1);
    for bytes in [invalid_shape.to_bytes()?, rejected.to_bytes()?] {
        let result =
            filestorage::verify_proof(runtime, &s2, bytes, vec![&challenge.challenge_id]).await?;
        let Err(Error::Message(message)) = result else {
            panic!("expected proof verification error");
        };
        assert_eq!(message, "Proof verification failed");
        assert_challenges_open(runtime, &[&challenge]).await?;
    }

    let malformed =
        filestorage::verify_proof(runtime, &s2, vec![0; 10], vec![&challenge.challenge_id]).await?;
    assert!(malformed.is_err());
    assert_challenges_open(runtime, &[&challenge]).await?;

    // Exercise the expiry hook locally without mining 2,016 regtest blocks.
    if runtime.runtime.reg_tester().is_none() {
        let core_signer = Signer::Core(Box::new(s1));
        let deadline = challenge.deadline_height;
        assert_eq!(
            filestorage::expire_challenges(runtime, &core_signer, deadline - 1).await?,
            0
        );
        assert_challenges_open(runtime, &[&challenge]).await?;
        assert_eq!(
            filestorage::expire_challenges(runtime, &core_signer, deadline).await?,
            1
        );
        assert_eq!(
            filestorage::expire_challenges(runtime, &core_signer, deadline).await?,
            0
        );
        let expired = filestorage::get_challenge(runtime, &challenge.challenge_id)
            .await?
            .unwrap();
        assert_eq!(expired.status, filestorage::ChallengeStatus::Expired);
        assert!(
            filestorage::get_agreement(runtime, &created2.agreement_id)
                .await?
                .unwrap()
                .active_challenge
                .is_none()
        );
        assert!(
            filestorage::verify_proof(runtime, &s2, proof_bytes, vec![&challenge.challenge_id])
                .await?
                .is_err()
        );
    }

    Ok(())
}

async fn assert_challenges_open(
    runtime: &mut Runtime,
    challenges: &[&filestorage::ChallengeData],
) -> Result<()> {
    let active = filestorage::get_active_challenges(runtime).await?;
    for challenge in challenges {
        let actual = filestorage::get_challenge(runtime, &challenge.challenge_id)
            .await?
            .unwrap();
        assert_eq!(actual.status, filestorage::ChallengeStatus::Active);
        assert_eq!(actual.deadline_height, challenge.deadline_height);
        assert!(
            active
                .iter()
                .any(|c| c.challenge_id == challenge.challenge_id)
        );
        let agreement = filestorage::get_agreement(runtime, &challenge.agreement_id)
            .await?
            .unwrap();
        assert_eq!(
            agreement.active_challenge.as_deref(),
            Some(challenge.challenge_id.as_str())
        );
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
async fn e2e_cross_block_aggregation_with_new_agreement(runtime: &mut Runtime) -> Result<()> {
    // Three distinct signers activate every agreement; `s1` is the common
    // member that proves both files, so its signer_id is the aggregated proof's
    // prover_id.
    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;

    // Step 1: Create files A and B (existing before the "middle" agreement)
    let (_prepared_a, metadata_a) =
        prepare_test_file(b"Content of file A for cross-block", "cross_a.txt");
    let (_prepared_b, metadata_b) =
        prepare_test_file(b"Content of file B for cross-block", "cross_b.txt");

    let created_a =
        filestorage::create_agreement(runtime, &s1, metadata_to_descriptor(&metadata_a)).await??;
    let created_b =
        filestorage::create_agreement(runtime, &s1, metadata_to_descriptor(&metadata_b)).await??;

    // Activate A and B; capture s1's signer_id (the prover) from A's join.
    let prover = filestorage::join_agreement(runtime, &s1, &created_a.agreement_id)
        .await??
        .node_id;
    filestorage::join_agreement(runtime, &s2, &created_a.agreement_id).await??;
    filestorage::join_agreement(runtime, &s3, &created_a.agreement_id).await??;
    filestorage::join_agreement(runtime, &s1, &created_b.agreement_id).await??;
    filestorage::join_agreement(runtime, &s2, &created_b.agreement_id).await??;
    filestorage::join_agreement(runtime, &s3, &created_b.agreement_id).await??;

    // Step 2: Create challenges for A and B at block N, for the common prover.
    let block_n = 40000u64;

    let challenge_a = filestorage::create_challenge_for_agreement(
        runtime,
        &s1,
        &created_a.agreement_id,
        prover,
        block_n,
        valid_seed_field(200).bytes.to_vec(),
    )
    .await??;

    let challenge_b = filestorage::create_challenge_for_agreement(
        runtime,
        &s1,
        &created_b.agreement_id,
        prover,
        block_n,
        valid_seed_field(201).bytes.to_vec(),
    )
    .await??;

    // Step 3: NEW AGREEMENT CREATED IN THE MIDDLE
    // File C is added after challenges were created but before proof generation
    let (_prepared_c, metadata_c) =
        prepare_test_file(b"Content of file C - new agreement", "cross_c.txt");

    let created_c =
        filestorage::create_agreement(runtime, &s1, metadata_to_descriptor(&metadata_c)).await??;
    filestorage::join_agreement(runtime, &s1, &created_c.agreement_id).await??;
    filestorage::join_agreement(runtime, &s2, &created_c.agreement_id).await??;
    filestorage::join_agreement(runtime, &s3, &created_c.agreement_id).await??;

    // Publish the current root over {A, B, C} before verifying. The fixture proves
    // against the full 3-file ledger, so the proof's ledger_root is this root and it
    // must be in the window. Per-block batching publishes only block-end roots, so
    // this must land in a block BEFORE verify_proof (create_agreement used to record
    // it inline). Local: no reactor — record via the core hook. Regtest: mine a block
    // so the reactor's run_block_lifecycle records it.
    match runtime.runtime.reg_tester() {
        None => {
            let core_signer = Signer::Core(Box::new(runtime.identity().await?));
            filestorage::record_block_root(runtime, &core_signer).await??;
        }
        Some(rt) => {
            rt.mine(1).await?;
        }
    }

    // Step 4: Generate the aggregated proof inline for `prover` over A and B (at
    // the network's challenge count), then verify it through the contract.
    let s_chal = filestorage::get_s_chal(runtime).await? as usize;
    let proof_bytes = por_cross_block_proof_bytes(prover, s_chal)?;
    let a = challenge_a.challenge_id.as_str();
    let b = challenge_b.challenge_id.as_str();
    for ids in [vec![], vec![a], vec![a, a, b], vec![a, "unregistered"]] {
        assert!(
            filestorage::verify_proof(runtime, &s2, proof_bytes.clone(), ids)
                .await?
                .is_err()
        );
        assert_challenges_open(runtime, &[&challenge_a, &challenge_b]).await?;
    }
    // v3 proofs no longer enumerate their challenges — the submitter declares the
    // ids the proof answers (A and B here).
    let result = filestorage::verify_proof(
        runtime,
        &s2,
        proof_bytes,
        vec![&challenge_a.challenge_id, &challenge_b.challenge_id],
    )
    .await??;

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
