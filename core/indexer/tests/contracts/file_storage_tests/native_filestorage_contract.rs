use indexer::test_utils::{LUCKY_HASH_50000, lucky_hash, make_descriptor, valid_seed_field};
use testlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/filestorage/wit",
);

fn has_node(nodes: &[filestorage::NodeInfo], node_id: u64, active: bool) -> bool {
    nodes
        .iter()
        .any(|n| n.node_id == node_id && n.active == active)
}

/// Join an agreement with `n` fresh distinct signers (one slot per signer);
/// returns their node_ids (the signers' u64 signer_id) in join order.
async fn join_n_distinct(runtime: &mut Runtime, agreement_id: &str, n: usize) -> Result<Vec<u64>> {
    let mut ids = Vec::new();
    for _ in 0..n {
        let s = runtime.identity().await?;
        let r = filestorage::join_agreement(runtime, &s, agreement_id).await??;
        ids.push(r.node_id);
    }
    Ok(ids)
}

async fn prepare_real_descriptor() -> Result<RawFileDescriptor> {
    let root: Vec<u8> = [0u8; 32].to_vec();
    let padded_len: u64 = 16; // 2^4
    Ok(make_descriptor(
        "test_file".to_string(),
        root,
        padded_len,
        100,
        "test_file.txt".to_string(),
    ))
}

async fn filestorage_defaults(runtime: &mut Runtime) -> Result<()> {
    // Protocol params should match defaults in the contract.
    assert_eq!(filestorage::get_min_nodes(runtime).await?, 3);
    assert_eq!(filestorage::get_c_target(runtime).await?, 12);
    assert_eq!(filestorage::get_blocks_per_year(runtime).await?, 52560);
    assert_eq!(filestorage::get_s_chal(runtime).await?, 8);

    // In local mode, no challenges should exist yet.
    // In regtest mode, prior tests on the shared cluster may have generated challenges.
    if runtime.reg_tester().is_none() {
        let active = filestorage::get_active_challenges(runtime).await?;
        assert!(active.is_empty());
    }

    // Unknown IDs should be safe.
    assert!(
        filestorage::get_agreement(runtime, "nonexistent")
            .await?
            .is_none()
    );
    assert!(
        filestorage::get_challenge(runtime, "nonexistent")
            .await?
            .is_none()
    );
    assert!(
        filestorage::get_agreement_nodes(runtime, "nonexistent")
            .await?
            .is_empty()
    );
    assert!(!filestorage::is_node_in_agreement(runtime, "nonexistent", 1).await?);

    Ok(())
}

async fn filestorage_empty_file_id_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "".to_string(),
        vec![0u8; 32],
        16,
        10,
        "empty.txt".to_string(),
    );
    let err = filestorage::create_agreement(runtime, &signer, descriptor).await?;
    assert!(matches!(err, Err(Error::Message(_))));
    Ok(())
}

async fn filestorage_get_all_active_agreements(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    // Create inactive agreement
    let a1 = filestorage::create_agreement(
        runtime,
        &signer,
        make_descriptor(
            "all_active_1".to_string(),
            vec![11u8; 32],
            16,
            10,
            "all_active_1.txt".to_string(),
        ),
    )
    .await??;
    let active = filestorage::get_all_active_agreements(runtime).await?;
    assert!(!active.iter().any(|a| a.agreement_id == a1.agreement_id));

    // Activate it by reaching min_nodes with three distinct signers
    join_n_distinct(runtime, &a1.agreement_id, 3).await?;
    let active = filestorage::get_all_active_agreements(runtime).await?;
    assert!(
        active
            .iter()
            .any(|a| a.agreement_id == a1.agreement_id && a.active)
    );

    // A second agreement that stays inactive should not be returned.
    let a2 = filestorage::create_agreement(
        runtime,
        &signer,
        make_descriptor(
            "all_active_2".to_string(),
            vec![12u8; 32],
            16,
            10,
            "all_active_2.txt".to_string(),
        ),
    )
    .await??;
    let active = filestorage::get_all_active_agreements(runtime).await?;
    assert!(!active.iter().any(|a| a.agreement_id == a2.agreement_id));

    Ok(())
}

async fn filestorage_create_and_get(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = prepare_real_descriptor().await?;

    let created = filestorage::create_agreement(runtime, &signer, descriptor.clone()).await??;
    assert_eq!(created.agreement_id, descriptor.file_id);

    let got = filestorage::get_agreement(runtime, created.agreement_id.as_str()).await?;
    let got = got.expect("agreement should exist");

    assert_eq!(got.agreement_id, created.agreement_id);
    assert_eq!(got.file_id, descriptor.file_id);
    assert!(!got.active);

    // Check nodes via separate function
    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert!(nodes.is_empty());
    Ok(())
}

async fn filestorage_count_increments(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    let c0 = filestorage::agreement_count(runtime).await?;
    let d1 = make_descriptor(
        "count_file_1".to_string(),
        vec![9u8; 32],
        16,
        100,
        "count_file_1.txt".to_string(),
    );
    filestorage::create_agreement(runtime, &signer, d1).await??;
    let c1 = filestorage::agreement_count(runtime).await?;
    assert_eq!(c1, c0 + 1);

    let d2 = make_descriptor(
        "another_file".to_string(),
        vec![7u8; 32],
        256,
        200,
        "another.txt".to_string(),
    );
    filestorage::create_agreement(runtime, &signer, d2).await??;
    let c2 = filestorage::agreement_count(runtime).await?;
    assert_eq!(c2, c1 + 1);

    Ok(())
}

async fn filestorage_duplicate_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "dup_file".to_string(),
        vec![1u8; 32],
        256,
        200,
        "dup.txt".to_string(),
    );

    filestorage::create_agreement(runtime, &signer, descriptor.clone()).await??;
    let err = filestorage::create_agreement(runtime, &signer, descriptor).await?;
    assert!(matches!(err, Err(Error::Message(_))));
    Ok(())
}

async fn filestorage_invalid_root_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "bad_root".to_string(),
        vec![1u8; 31],
        256,
        200,
        "bad.txt".to_string(),
    );

    let err = filestorage::create_agreement(runtime, &signer, descriptor).await?;
    assert!(matches!(err, Err(Error::Validation(_))));
    Ok(())
}

async fn filestorage_invalid_padded_len_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    // padded_len = 0 should fail
    let descriptor = make_descriptor(
        "zero_padded".to_string(),
        vec![1u8; 32],
        0,
        0,
        "zero.txt".to_string(),
    );
    let err = filestorage::create_agreement(runtime, &signer, descriptor).await?;
    assert!(matches!(err, Err(Error::Message(_))));

    // padded_len not a power of 2 should fail
    let descriptor = make_descriptor(
        "bad_padded".to_string(),
        vec![1u8; 32],
        15,
        10,
        "bad.txt".to_string(),
    );
    let err = filestorage::create_agreement(runtime, &signer, descriptor).await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Node Join/Leave Tests
// ─────────────────────────────────────────────────────────────────

async fn filestorage_join_agreement(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "join_test".to_string(),
        vec![2u8; 32],
        16,
        10,
        "join.txt".to_string(),
    );

    // Create agreement
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;

    // Join with first node
    let result = filestorage::join_agreement(runtime, &signer, &created.agreement_id).await??;
    assert_eq!(result.agreement_id, created.agreement_id);
    let n1 = result.node_id;
    assert!(!result.activated); // Not activated yet (need 3 nodes by default)

    // Verify node is in agreement
    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    let agreement = agreement.expect("agreement should exist");
    assert!(!agreement.active);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 1);
    assert!(has_node(&nodes, n1, true));

    Ok(())
}

async fn filestorage_join_activates_at_min_nodes(runtime: &mut Runtime) -> Result<()> {
    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;
    let descriptor = make_descriptor(
        "activate_test".to_string(),
        vec![3u8; 32],
        16,
        10,
        "activate.txt".to_string(),
    );

    // Create agreement
    let created = filestorage::create_agreement(runtime, &s1, descriptor).await??;

    // Get min_nodes
    let min_nodes = filestorage::get_min_nodes(runtime).await?;
    assert_eq!(min_nodes, 3); // Default

    // Join with distinct signers until activation
    let result1 = filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    assert!(!result1.activated);
    let n1 = result1.node_id;

    let result2 = filestorage::join_agreement(runtime, &s2, &created.agreement_id).await??;
    assert!(!result2.activated);
    let n2 = result2.node_id;

    let result3 = filestorage::join_agreement(runtime, &s3, &created.agreement_id).await??;
    assert!(result3.activated); // Should activate now!
    let n3 = result3.node_id;

    // Verify agreement is active
    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    let agreement = agreement.expect("agreement should exist");
    assert!(agreement.active);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 3);
    assert!(has_node(&nodes, n1, true));
    assert!(has_node(&nodes, n2, true));
    assert!(has_node(&nodes, n3, true));

    Ok(())
}

async fn filestorage_double_join_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "double_join_test".to_string(),
        vec![4u8; 32],
        16,
        10,
        "double.txt".to_string(),
    );

    // Create agreement and join once with this signer
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id).await??;

    // The same signer joining the same agreement again should fail
    // (one membership slot per signer).
    let err = filestorage::join_agreement(runtime, &signer, &created.agreement_id).await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_join_nonexistent_agreement_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    let err = filestorage::join_agreement(runtime, &signer, "nonexistent").await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_leave_agreement(runtime: &mut Runtime) -> Result<()> {
    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let descriptor = make_descriptor(
        "leave_test".to_string(),
        vec![5u8; 32],
        16,
        10,
        "leave.txt".to_string(),
    );

    // Create agreement and join with two distinct signers
    let created = filestorage::create_agreement(runtime, &s1, descriptor).await??;
    let r1 = filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    let r2 = filestorage::join_agreement(runtime, &s2, &created.agreement_id).await??;

    // s1 leaves its own membership
    let result = filestorage::leave_agreement(runtime, &s1, &created.agreement_id).await??;
    assert_eq!(result.agreement_id, created.agreement_id);
    assert_eq!(result.node_id, r1.node_id);

    // Verify s1's node is removed, s2's remains active
    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 2);
    assert!(has_node(&nodes, r1.node_id, false));
    assert!(has_node(&nodes, r2.node_id, true));

    Ok(())
}

async fn filestorage_leave_nonmember_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "leave_nonmember_test".to_string(),
        vec![6u8; 32],
        16,
        10,
        "leave_nonmember.txt".to_string(),
    );

    // Create agreement
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;

    // Try to leave without joining
    let err = filestorage::leave_agreement(runtime, &signer, &created.agreement_id).await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_leave_nonexistent_agreement_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    let err = filestorage::leave_agreement(runtime, &signer, "nonexistent").await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_leave_does_not_deactivate(runtime: &mut Runtime) -> Result<()> {
    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;
    let descriptor = make_descriptor(
        "no_deactivate_test".to_string(),
        vec![7u8; 32],
        16,
        10,
        "no_deactivate.txt".to_string(),
    );

    // Create agreement and activate it with three distinct signers
    let created = filestorage::create_agreement(runtime, &s1, descriptor).await??;
    let r1 = filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    let r2 = filestorage::join_agreement(runtime, &s2, &created.agreement_id).await??;
    let r3 = filestorage::join_agreement(runtime, &s3, &created.agreement_id).await??;

    // Verify active
    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    assert!(agreement.expect("exists").active);

    // Leave nodes until below min_nodes (each signer leaves its own membership)
    filestorage::leave_agreement(runtime, &s1, &created.agreement_id).await??;
    filestorage::leave_agreement(runtime, &s2, &created.agreement_id).await??;

    // Agreement should still be active (no deactivation)
    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    let agreement = agreement.expect("agreement should exist");
    assert!(agreement.active); // Still active!

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 3);
    assert!(has_node(&nodes, r1.node_id, false));
    assert!(has_node(&nodes, r2.node_id, false));
    assert!(has_node(&nodes, r3.node_id, true));

    Ok(())
}

async fn filestorage_is_node_in_agreement(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "is_node_test".to_string(),
        vec![8u8; 32],
        16,
        10,
        "is_node.txt".to_string(),
    );

    // Create agreement
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;

    // Join node
    let joined = filestorage::join_agreement(runtime, &signer, &created.agreement_id).await??;
    let n1 = joined.node_id;

    // Node should be in agreement
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, n1).await?;
    assert!(is_in);

    // Leave node
    filestorage::leave_agreement(runtime, &signer, &created.agreement_id).await??;

    // Node should no longer be in agreement
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, n1).await?;
    assert!(!is_in);

    Ok(())
}

async fn filestorage_is_node_in_nonexistent_agreement(runtime: &mut Runtime) -> Result<()> {
    // Checking a nonexistent agreement should return false, not error
    let is_in = filestorage::is_node_in_agreement(runtime, "nonexistent", 1).await?;
    assert!(!is_in);

    Ok(())
}

async fn filestorage_rejoin_after_leave(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "rejoin_test".to_string(),
        vec![9u8; 32],
        16,
        10,
        "rejoin.txt".to_string(),
    );

    // Create agreement and join
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;
    let joined = filestorage::join_agreement(runtime, &signer, &created.agreement_id).await??;
    let n1 = joined.node_id;

    // Verify node is in
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, n1).await?;
    assert!(is_in);

    // Leave
    filestorage::leave_agreement(runtime, &signer, &created.agreement_id).await??;

    // Verify node is out
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, n1).await?;
    assert!(!is_in);

    // Rejoin - should succeed (same signer gets the same node_id)
    let result = filestorage::join_agreement(runtime, &signer, &created.agreement_id).await??;
    assert_eq!(result.node_id, n1);

    // Verify node is back in
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, n1).await?;
    assert!(is_in);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 1);

    Ok(())
}

async fn filestorage_join_after_activation_not_reactivated(runtime: &mut Runtime) -> Result<()> {
    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;
    let s4 = runtime.identity().await?;
    let descriptor = make_descriptor(
        "no_reactivate_test".to_string(),
        vec![10u8; 32],
        16,
        10,
        "no_reactivate.txt".to_string(),
    );

    // Create and activate agreement with three distinct signers
    let created = filestorage::create_agreement(runtime, &s1, descriptor).await??;
    filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    filestorage::join_agreement(runtime, &s2, &created.agreement_id).await??;
    let result3 = filestorage::join_agreement(runtime, &s3, &created.agreement_id).await??;
    assert!(result3.activated); // Third node activates

    // Fourth distinct signer joining should NOT report activated (already active)
    let result4 = filestorage::join_agreement(runtime, &s4, &created.agreement_id).await??;
    assert!(!result4.activated); // Already active, so activated=false

    // Agreement should still be active
    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    assert!(agreement.expect("exists").active);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 4);

    Ok(())
}

async fn challenge_gen_smoke_test(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let core_identity = runtime.identity().await?;
    let core_signer = Signer::Core(Box::new(core_identity));

    // Create an active agreement (use small root value - large ones exceed field modulus)
    let descriptor = make_descriptor(
        "challenge_smoke_test".to_string(),
        vec![1u8; 32],
        16,
        100,
        "smoke.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;

    // Activate it with three distinct signers
    join_n_distinct(runtime, &created.agreement_id, 3).await?;

    let block_hash = vec![1u8; 32];
    let before_active = filestorage::get_active_challenges(runtime).await?;
    // Core-only: generate challenges requires core signer
    let challenges =
        filestorage::generate_challenges_for_block(runtime, &core_signer, 1000, block_hash).await?;

    // Verify the return type is correct (list of challenges, possibly empty)
    assert!(challenges.len() <= 1, "Should have 0 or 1 challenges");

    // Verify get_active_challenges works
    let after_active = filestorage::get_active_challenges(runtime).await?;
    assert_eq!(after_active.len(), before_active.len() + challenges.len());

    // Core-only: expire_challenges requires core signer
    filestorage::expire_challenges(runtime, &core_signer, 10000).await?;

    Ok(())
}

/// Test that uses a pre-computed "lucky" block hash to guarantee challenge generation.
/// This verifies the challenge generation formula works correctly.
async fn challenge_gen_with_lucky_hash(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let core_identity = runtime.identity().await?;
    let core_signer = Signer::Core(Box::new(core_identity));

    // Create an active agreement
    let descriptor = make_descriptor(
        "lucky_hash_test".to_string(),
        vec![1u8; 32],
        16,
        100,
        "lucky.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;

    // Activate it with min_nodes (3) distinct signers
    join_n_distinct(runtime, &created.agreement_id, 3).await?;

    // Use a pre-computed block hash that will definitely generate a challenge for 1 file
    // With 1 eligible file and c_target=12, blocks_per_year=52560:
    //   remainder = 12, so challenge generated when roll < 12
    // LUCKY_HASH_50000 has roll = 1, which is < 12
    let block_height = 50000u64;
    let block_hash = lucky_hash(LUCKY_HASH_50000);

    let before_active = filestorage::get_active_challenges(runtime).await?;
    assert_eq!(
        before_active.len(),
        0,
        "Should start with no active challenges"
    );

    // Generate challenges with the lucky hash - should definitely produce 1 challenge
    let challenges = filestorage::generate_challenges_for_block(
        runtime,
        &core_signer,
        block_height,
        block_hash.to_vec(),
    )
    .await?;

    // With a lucky hash, we should get exactly 1 challenge
    assert_eq!(
        challenges.len(),
        1,
        "Lucky hash should generate exactly 1 challenge"
    );

    // Verify the challenge details
    let challenge = &challenges[0];
    assert_eq!(challenge.agreement_id, created.agreement_id);
    assert_eq!(challenge.block_height, block_height);
    assert_eq!(challenge.status, filestorage::ChallengeStatus::Active);

    // Verify get_active_challenges reflects the new challenge
    let after_active = filestorage::get_active_challenges(runtime).await?;
    assert_eq!(after_active.len(), 1);

    Ok(())
}

/// Challenge selection must SKIP an agreement that already has an active challenge
/// (the ≤1-active-challenge-per-agreement invariant) and exclude it from the eligible
/// count. Two active agreements, one already challenged: a generating block lands its
/// single challenge on the OTHER, and never gives the challenged one a second. Exercises
/// the new dense-array rejection sampler + the `active_count - challenged` count path.
async fn challenge_gen_skips_already_challenged(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let core_signer = Signer::Core(Box::new(runtime.identity().await?));

    let a = filestorage::create_agreement(
        runtime,
        &signer,
        make_descriptor("skip_a".into(), vec![1u8; 32], 16, 100, "a.txt".into()),
    )
    .await??;
    let a_nodes = join_n_distinct(runtime, &a.agreement_id, 3).await?;

    let b = filestorage::create_agreement(
        runtime,
        &signer,
        make_descriptor("skip_b".into(), vec![1u8; 32], 16, 100, "b.txt".into()),
    )
    .await??;
    join_n_distinct(runtime, &b.agreement_id, 3).await?;

    // Challenge A directly → A is now ineligible.
    filestorage::create_challenge_for_agreement(
        runtime,
        &signer,
        &a.agreement_id,
        a_nodes[0],
        1000,
        valid_seed_field(1).bytes.to_vec(),
    )
    .await??;
    assert_eq!(filestorage::get_active_challenges(runtime).await?.len(), 1);

    // One eligible file (B) + the lucky hash → exactly one challenge, and the sampler
    // must skip A's ordinal and select B.
    let challenges = filestorage::generate_challenges_for_block(
        runtime,
        &core_signer,
        50000,
        lucky_hash(LUCKY_HASH_50000).to_vec(),
    )
    .await?;
    assert_eq!(challenges.len(), 1, "one eligible file → one challenge");
    assert_eq!(
        challenges[0].agreement_id, b.agreement_id,
        "must skip the already-challenged A and select B"
    );

    // A was never double-challenged; total active challenges is now 2 (A's + B's new one).
    assert_eq!(filestorage::get_active_challenges(runtime).await?.len(), 2);
    Ok(())
}

pub async fn run_regtest(runtime: &mut Runtime) -> Result<()> {
    filestorage_defaults(runtime).await?;
    filestorage_empty_file_id_fails(runtime).await?;
    filestorage_get_all_active_agreements(runtime).await?;
    filestorage_create_and_get(runtime).await?;
    filestorage_count_increments(runtime).await?;
    filestorage_duplicate_fails(runtime).await?;
    filestorage_invalid_root_fails(runtime).await?;
    filestorage_invalid_padded_len_fails(runtime).await?;
    filestorage_join_agreement(runtime).await?;
    filestorage_join_activates_at_min_nodes(runtime).await?;
    filestorage_double_join_fails(runtime).await?;
    filestorage_join_nonexistent_agreement_fails(runtime).await?;
    filestorage_leave_agreement(runtime).await?;
    filestorage_leave_nonmember_fails(runtime).await?;
    filestorage_leave_nonexistent_agreement_fails(runtime).await?;
    filestorage_leave_does_not_deactivate(runtime).await?;
    filestorage_is_node_in_agreement(runtime).await?;
    filestorage_is_node_in_nonexistent_agreement(runtime).await?;
    filestorage_rejoin_after_leave(runtime).await?;
    filestorage_join_after_activation_not_reactivated(runtime).await?;
    Ok(())
}

pub async fn run_core_signer_smoke(runtime: &mut Runtime) -> Result<()> {
    challenge_gen_smoke_test(runtime).await
}

pub async fn run_core_signer_skip_challenged(runtime: &mut Runtime) -> Result<()> {
    challenge_gen_skips_already_challenged(runtime).await
}

pub async fn run_core_signer_lucky(runtime: &mut Runtime) -> Result<()> {
    challenge_gen_with_lucky_hash(runtime).await
}
