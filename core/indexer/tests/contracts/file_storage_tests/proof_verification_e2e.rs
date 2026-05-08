//! End-to-end proof verification integration tests.
//!
//! These tests exercise the full proof-of-retrievability flow:
//! 1. Prepare files using kontor-crypto
//! 2. Create agreements in the filestorage contract
//! 3. Generate challenges through the contract
//! 4. Generate matching proofs inline via `PorSystem`
//! 5. Verify proofs through the contract
//!
//! Proofs are generated in-test (not loaded from a fixture) because the
//! prover-id is now `signer.to_string()` (a runtime-allocated integer) and
//! enters challenge-id derivation, so a static fixture cannot match.

use indexer::database::types::field_element_to_bytes;
use indexer::test_utils::valid_seed_field;
use kontor_crypto::api::{self, Challenge as CryptoChallenge};
use kontor_crypto::{FileLedger, PorSystem};
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

/// Build a kontor-crypto Proof for the given prepared files + challenges and
/// return its wire bytes. The caller is responsible for ensuring the
/// kontor-crypto FileLedger contains the same files in the same order as the
/// contract-side ledger at challenge time.
fn build_proof_bytes(
    ledger: &FileLedger,
    files: Vec<&api::PreparedFile>,
    challenges: &[CryptoChallenge],
) -> Result<Vec<u8>> {
    let system = PorSystem::new(ledger);
    let proof = system
        .prove(files, challenges)
        .map_err(|e| anyhow!("Failed to generate proof: {e}"))?;
    proof
        .to_bytes()
        .map_err(|e| anyhow!("Failed to serialize proof: {e}"))
}

/// The contract derives `shard_id` from the first byte of the hex-encoded
/// `Challenge::id()`. Mirror that here so tests can search for seeds that
/// place two challenges on the same shard (required for aggregation).
fn challenge_shard_id_for(
    metadata: &api::FileMetadata,
    block_height: u64,
    num_challenges: usize,
    seed: kontor_crypto::FieldElement,
    prover_id: &str,
) -> u8 {
    let ch = CryptoChallenge::new(
        metadata.clone(),
        block_height,
        num_challenges,
        seed,
        prover_id.to_string(),
    );
    ch.id().0[0]
}

/// Search for a `(seed_a_index, seed_b_index)` pair such that the resulting
/// challenges for `metadata_a` and `metadata_b` (with the same prover/block
/// parameters) share a kontor-crypto shard. Panics if no pair is found
/// within the search bounds — in practice ~256 iterations suffice with
/// NUM_CHALLENGES_SHARDS=256.
fn find_co_sharded_seeds(
    metadata_a: &api::FileMetadata,
    metadata_b: &api::FileMetadata,
    block_height: u64,
    num_challenges: usize,
    prover_id: &str,
) -> (u64, u64) {
    let seed_a_index: u64 = 0xA00;
    let seed_a = valid_seed_field(seed_a_index);
    let target_shard = challenge_shard_id_for(
        metadata_a,
        block_height,
        num_challenges,
        seed_a.field,
        prover_id,
    );
    for i in 0..10_000u64 {
        let candidate_b = 0xB00 + i;
        let seed_b = valid_seed_field(candidate_b);
        let shard_b = challenge_shard_id_for(
            metadata_b,
            block_height,
            num_challenges,
            seed_b.field,
            prover_id,
        );
        if shard_b == target_shard {
            return (seed_a_index, candidate_b);
        }
    }
    panic!(
        "Could not find co-sharded seeds for prover_id={} after 10000 iterations",
        prover_id
    );
}

// ─────────────────────────────────────────────────────────────────
// Invalid Proof Returns Rejected
// ─────────────────────────────────────────────────────────────────

async fn e2e_invalid_proof_rejected(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let node_1_signer = runtime.identity().await?;
    let node_2_signer = runtime.identity().await?;
    let node_3_signer = runtime.identity().await?;

    let file2_content = b"Second file with different content";
    let (_prepared_file2, metadata2) = prepare_test_file(file2_content, "file2.txt");

    let descriptor2 = metadata_to_descriptor(&metadata2);
    let created2 = filestorage::create_agreement(runtime, &signer, descriptor2).await??;

    let mut submit = runtime.submit();
    for node in [&node_1_signer, &node_2_signer, &node_3_signer] {
        let mut ops = Ops::new(node);
        ops.push(filestorage::join_agreement_call(&created2.agreement_id));
        submit.add(ops);
    }
    submit.execute().await?;

    // Garbage bytes — the test just asserts the contract rejects them.
    let proof_bytes = vec![0u8; 200];
    let result = filestorage::verify_proof(runtime, &node_1_signer, proof_bytes, 0, 0, 1).await?;
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
///
/// Local-only: drives challenge creation via `create_challenge_for_agreement`,
/// which takes a `borrow<core-context>` and is only reachable when the
/// indexer dispatches the call directly with a `Signer::Core(_)`. Regtest
/// dispatches every contract call via a Bitcoin tx (always `Signer::Id`),
/// so the core-context export is unreachable there.
async fn e2e_cross_block_aggregation_with_new_agreement(runtime: &mut Runtime) -> Result<()> {
    if runtime.reg_tester().is_some() {
        return Ok(());
    }
    let signer = runtime.identity().await?;
    let core_identity = runtime.identity().await?;
    let core_signer = Signer::Core(Box::new(core_identity));
    let node_1_signer = runtime.identity().await?;
    let node_2_signer = runtime.identity().await?;
    let node_3_signer = runtime.identity().await?;
    let node_1_id = node_1_signer.to_string();

    let (prepared_a, metadata_a) =
        prepare_test_file(b"Content of file A for cross-block", "cross_a.txt");
    let (prepared_b, metadata_b) =
        prepare_test_file(b"Content of file B for cross-block", "cross_b.txt");

    let descriptor_a = metadata_to_descriptor(&metadata_a);
    let created_a = filestorage::create_agreement(runtime, &signer, descriptor_a).await??;

    let descriptor_b = metadata_to_descriptor(&metadata_b);
    let created_b = filestorage::create_agreement(runtime, &signer, descriptor_b).await??;

    // Activate both agreements with three distinct node-signers
    let mut submit = runtime.submit();
    for agreement_id in [&created_a.agreement_id, &created_b.agreement_id] {
        for node in [&node_1_signer, &node_2_signer, &node_3_signer] {
            let mut ops = Ops::new(node);
            ops.push(filestorage::join_agreement_call(agreement_id));
            submit.add(ops);
        }
    }
    submit.execute().await?;

    // Step 2: Create challenges for A and B at block N, targeting node_1's signer-id
    let block_n = 40000u64;
    let s_chal = filestorage::get_s_chal(runtime).await? as usize;

    // Aggregated proofs require both challenges to live on the same shard,
    // and the kontor-crypto shard depends on the prover-id (now a runtime
    // signer string). Search seeds at runtime so we don't rely on luck.
    let (seed_a_index, seed_b_index) =
        find_co_sharded_seeds(&metadata_a, &metadata_b, block_n, s_chal, &node_1_id);
    let seed_a = valid_seed_field(seed_a_index);
    let seed_b = valid_seed_field(seed_b_index);

    let challenge_a = filestorage::create_challenge_for_agreement(
        runtime,
        &core_signer,
        &created_a.agreement_id,
        &node_1_id,
        block_n,
        seed_a.bytes.to_vec(),
    )
    .await??;

    let challenge_b = filestorage::create_challenge_for_agreement(
        runtime,
        &core_signer,
        &created_b.agreement_id,
        &node_1_id,
        block_n,
        seed_b.bytes.to_vec(),
    )
    .await??;

    // Step 3: Build a matching kontor-crypto FileLedger and aggregated proof
    // for [A, B]. The contract-side ledger currently contains exactly [A, B];
    // we capture the proof's `ledger_root` against that state, then add file
    // C below so the contract verifies the proof's root via its historical
    // roots set rather than its current root.
    let mut crypto_ledger = FileLedger::new();
    crypto_ledger
        .add_file(&metadata_a)
        .map_err(|e| anyhow!("crypto add_file A: {e}"))?;
    crypto_ledger
        .add_file(&metadata_b)
        .map_err(|e| anyhow!("crypto add_file B: {e}"))?;

    let crypto_challenges = vec![
        CryptoChallenge::new(metadata_a, block_n, s_chal, seed_a.field, node_1_id.clone()),
        CryptoChallenge::new(metadata_b, block_n, s_chal, seed_b.field, node_1_id.clone()),
    ];

    let proof_bytes = build_proof_bytes(
        &crypto_ledger,
        vec![&prepared_a, &prepared_b],
        &crypto_challenges,
    )?;

    // Step 4: NEW AGREEMENT CREATED IN THE MIDDLE
    // File C is added after the proof was generated, advancing the contract
    // ledger past the proof's ledger_root.
    let (_prepared_c, metadata_c) =
        prepare_test_file(b"Content of file C - new agreement", "cross_c.txt");

    let descriptor_c = metadata_to_descriptor(&metadata_c);
    let created_c = filestorage::create_agreement(runtime, &signer, descriptor_c).await??;

    let mut submit = runtime.submit();
    for node in [&node_1_signer, &node_2_signer, &node_3_signer] {
        let mut ops = Ops::new(node);
        ops.push(filestorage::join_agreement_call(&created_c.agreement_id));
        submit.add(ops);
    }
    submit.execute().await?;

    // Step 5: Verify the inline-generated proof through the contract
    assert_eq!(
        challenge_a.shard_id, challenge_b.shard_id,
        "Aggregated proof expects challenges from a single shard"
    );
    let start_seq = challenge_a.shard_seq.min(challenge_b.shard_seq);
    let end_seq = challenge_a.shard_seq.max(challenge_b.shard_seq) + 1;
    let result = filestorage::verify_proof(
        runtime,
        &node_1_signer,
        proof_bytes,
        challenge_a.shard_id,
        start_seq,
        end_seq,
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
