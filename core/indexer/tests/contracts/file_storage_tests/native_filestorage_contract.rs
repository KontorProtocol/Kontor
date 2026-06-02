use indexer::test_utils::{LUCKY_HASH_50000, lucky_hash, make_descriptor};
use testlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/filestorage/wit",
);

fn has_node(nodes: &[filestorage::NodeInfo], node_id: &str, active: bool) -> bool {
    nodes
        .iter()
        .any(|n| n.node_id == node_id && n.active == active)
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
    assert_eq!(filestorage::get_s_chal(runtime).await?, 100);
    assert_eq!(filestorage::get_lambda_slash(runtime).await?, 30);

    // In local mode, no challenges should exist yet.
    // In regtest mode, prior tests on the shared cluster may have generated challenges.
    if runtime.reg_tester().is_none() {
        let active = filestorage::get_active_challenges(runtime).await?;
        assert!(active.is_empty());
        // No proofs have been rejected, so the slashable set is empty too.
        let failed = filestorage::get_failed_challenges(runtime).await?;
        assert!(failed.is_empty());
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
    assert!(!filestorage::is_node_in_agreement(runtime, "nonexistent", "node_1").await?);

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

    // Activate it by reaching min_nodes
    let mut ops = Ops::new(&signer);
    ops.push(filestorage::join_agreement_call(&a1.agreement_id, "node_1"));
    ops.push(filestorage::join_agreement_call(&a1.agreement_id, "node_2"));
    ops.push(filestorage::join_agreement_call(&a1.agreement_id, "node_3"));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;
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
    let result =
        filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    assert_eq!(result.agreement_id, created.agreement_id);
    assert_eq!(result.node_id, "node_1");
    assert!(!result.activated); // Not activated yet (need 3 nodes by default)

    // Verify node is in agreement
    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    let agreement = agreement.expect("agreement should exist");
    assert!(!agreement.active);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 1);
    assert!(has_node(&nodes, "node_1", true));

    Ok(())
}

async fn filestorage_join_activates_at_min_nodes(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "activate_test".to_string(),
        vec![3u8; 32],
        16,
        10,
        "activate.txt".to_string(),
    );

    // Create agreement
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;

    // Get min_nodes
    let min_nodes = filestorage::get_min_nodes(runtime).await?;
    assert_eq!(min_nodes, 3); // Default

    // Join with nodes until activation
    let result1 =
        filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    assert!(!result1.activated);

    let result2 =
        filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_2").await??;
    assert!(!result2.activated);

    let result3 =
        filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_3").await??;
    assert!(result3.activated); // Should activate now!

    // Verify agreement is active
    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    let agreement = agreement.expect("agreement should exist");
    assert!(agreement.active);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 3);
    assert!(has_node(&nodes, "node_1", true));
    assert!(has_node(&nodes, "node_2", true));
    assert!(has_node(&nodes, "node_3", true));

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

    // Create agreement and join
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;

    // Try to join again with same node
    let err =
        filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_join_nonexistent_agreement_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    let err = filestorage::join_agreement(runtime, &signer, "nonexistent", "node_1").await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_leave_agreement(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "leave_test".to_string(),
        vec![5u8; 32],
        16,
        10,
        "leave.txt".to_string(),
    );

    // Create agreement and join four nodes, so a single departure stays above
    // n_min (3) and is therefore permitted.
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;
    let mut ops = Ops::new(&signer);
    for n in ["node_1", "node_2", "node_3", "node_4"] {
        ops.push(filestorage::join_agreement_call(&created.agreement_id, n));
    }
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    // Leave with node_1 — allowed (|N_f| = 4 > n_min); charges the φ_leave fee.
    let result =
        filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    assert_eq!(result.agreement_id, created.agreement_id);
    assert_eq!(result.node_id, "node_1");
    let zero: Decimal = 0u64.try_into().unwrap();
    assert!(result.fee > zero, "φ_leave fee charged");

    // Verify node is removed
    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 4);
    assert!(has_node(&nodes, "node_1", false));
    assert!(has_node(&nodes, "node_2", true));

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
    let err =
        filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_1").await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_leave_nonexistent_agreement_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    let err = filestorage::leave_agreement(runtime, &signer, "nonexistent", "node_1").await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_leave_blocked_at_min_replication(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "min_repl_test".to_string(),
        vec![7u8; 32],
        16,
        10,
        "min_repl.txt".to_string(),
    );

    // Activate at exactly n_min (3) nodes — the replication floor.
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;
    let mut ops = Ops::new(&signer);
    for n in ["node_1", "node_2", "node_3"] {
        ops.push(filestorage::join_agreement_call(&created.agreement_id, n));
    }
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;
    assert!(
        filestorage::get_agreement(runtime, &created.agreement_id)
            .await?
            .expect("exists")
            .active
    );

    // Leaving at |N_f| = n_min is forbidden (would violate minimum replication).
    let err =
        filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_1").await?;
    assert!(
        matches!(err, Err(Error::Message(_))),
        "cannot leave at minimum replication"
    );

    // Add a 4th node; now a single departure is permitted again.
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_4").await??;
    filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert!(has_node(&nodes, "node_1", false));
    assert_eq!(
        nodes.iter().filter(|n| n.active).count(),
        3,
        "3 active after add + leave"
    );

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

    // Node not in agreement yet
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, "node_1").await?;
    assert!(!is_in);

    // Join node
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;

    // Node should be in agreement
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, "node_1").await?;
    assert!(is_in);

    // Leave node
    filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;

    // Node should no longer be in agreement
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, "node_1").await?;
    assert!(!is_in);

    Ok(())
}

async fn filestorage_is_node_in_nonexistent_agreement(runtime: &mut Runtime) -> Result<()> {
    // Checking a nonexistent agreement should return false, not error
    let is_in = filestorage::is_node_in_agreement(runtime, "nonexistent", "node_1").await?;
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
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;

    // Verify node is in
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, "node_1").await?;
    assert!(is_in);

    // Leave
    filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;

    // Verify node is out
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, "node_1").await?;
    assert!(!is_in);

    // Rejoin - should succeed
    let result =
        filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    assert_eq!(result.node_id, "node_1");

    // Verify node is back in
    let is_in = filestorage::is_node_in_agreement(runtime, &created.agreement_id, "node_1").await?;
    assert!(is_in);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 1);

    Ok(())
}

async fn filestorage_join_after_activation_not_reactivated(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "no_reactivate_test".to_string(),
        vec![10u8; 32],
        16,
        10,
        "no_reactivate.txt".to_string(),
    );

    // Create and activate agreement
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;
    let mut ops = Ops::new(&signer);
    ops.push(filestorage::join_agreement_call(
        &created.agreement_id,
        "node_1",
    ));
    ops.push(filestorage::join_agreement_call(
        &created.agreement_id,
        "node_2",
    ));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;
    let result3 =
        filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_3").await??;
    assert!(result3.activated); // Third node activates

    // Fourth join should NOT report activated (already active)
    let result4 =
        filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_4").await??;
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

    // Activate it
    let mut ops = Ops::new(&signer);
    ops.push(filestorage::join_agreement_call(
        &created.agreement_id,
        "node_0",
    ));
    ops.push(filestorage::join_agreement_call(
        &created.agreement_id,
        "node_1",
    ));
    ops.push(filestorage::join_agreement_call(
        &created.agreement_id,
        "node_2",
    ));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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

    // Activate it with min_nodes (3)
    let mut ops = Ops::new(&signer);
    ops.push(filestorage::join_agreement_call(
        &created.agreement_id,
        "node_0",
    ));
    ops.push(filestorage::join_agreement_call(
        &created.agreement_id,
        "node_1",
    ));
    ops.push(filestorage::join_agreement_call(
        &created.agreement_id,
        "node_2",
    ));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

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

/// The node ↔ staking-identity coupling: a membership is bound to the joining
/// signer's identity (resolvable for slashing), and each membership reserves the
/// agreement's per-node base stake k_f, released on leave.
async fn filestorage_node_staking_coupling(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let created = filestorage::create_agreement(
        runtime,
        &signer,
        make_descriptor(
            "coupling_test".to_string(),
            vec![7u8; 32],
            16,
            100,
            "coupling.txt".to_string(),
        ),
    )
    .await??;
    let zero: Decimal = 0u64.try_into().unwrap();
    let id = signer.to_string();

    // No reservation before joining.
    assert_eq!(filestorage::get_node_reservation(runtime, &id).await?, zero);

    // Join node_1 → membership bound to the signer's staking identity; k_f reserved.
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    assert_eq!(
        filestorage::get_node_owner(runtime, &created.agreement_id, "node_1").await?,
        Some(id.clone()),
        "membership bound to the joiner's staking identity"
    );
    let r1 = filestorage::get_node_reservation(runtime, &id).await?;
    assert!(r1 > zero, "k_f reserved on join");

    // Unknown node has no owner.
    assert_eq!(
        filestorage::get_node_owner(runtime, &created.agreement_id, "ghost").await?,
        None
    );

    // A second membership accumulates another k_f against the same identity.
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_2").await??;
    let r2 = filestorage::get_node_reservation(runtime, &id).await?;
    assert!(r2 > r1, "second membership reserves additional collateral");

    // Leaving (inactive agreement → fee-free) releases exactly that membership's k_f.
    filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    assert_eq!(
        filestorage::get_node_reservation(runtime, &id).await?,
        r1,
        "leaving releases one k_f back to the single-membership reservation"
    );

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
    filestorage_leave_blocked_at_min_replication(runtime).await?;
    filestorage_is_node_in_agreement(runtime).await?;
    filestorage_is_node_in_nonexistent_agreement(runtime).await?;
    filestorage_rejoin_after_leave(runtime).await?;
    filestorage_join_after_activation_not_reactivated(runtime).await?;
    filestorage_node_staking_coupling(runtime).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Storage Economics Tests
// ─────────────────────────────────────────────────────────────────

/// Exercises the storage-emission weights (ω_f, k_f), the Ω accumulator, and
/// reward distribution. Assumes a fresh runtime (run first in the aggregator).
async fn storage_economics_smoke(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let core_identity = runtime.identity().await?;
    let core_signer = Signer::Core(Box::new(core_identity));

    // Genesis economics: parameter defaults and Ω == Ω_genesis, no active files.
    let params = filestorage::get_storage_params(runtime).await?;
    assert_eq!(params.omega_genesis, 1000);
    assert_eq!(params.r_offset, 1000);
    assert_eq!(params.f_scale, 1000);
    assert_eq!(params.chi_fee_bps, 30); // χ_fee = 0.3%
    let omega0 = filestorage::get_omega(runtime).await?;
    assert_eq!(omega0, 1000u64.try_into().unwrap());
    let files0 = filestorage::get_active_file_count(runtime).await?;
    assert_eq!(files0, 0);

    // Distributing into a network with no active files yields nothing.
    let empty = filestorage::distribute_storage_rewards(
        runtime,
        &core_signer,
        1_000_000u64.try_into().unwrap(),
    )
    .await??;
    assert!(empty.is_empty());

    // Create a large then a small file. Weights are fixed at creation.
    let big = filestorage::create_agreement(
        runtime,
        &signer,
        make_descriptor(
            "econ_big".to_string(),
            vec![20u8; 32],
            16,
            1_000_000,
            "big.bin".to_string(),
        ),
    )
    .await??;
    let small = filestorage::create_agreement(
        runtime,
        &signer,
        make_descriptor(
            "econ_small".to_string(),
            vec![21u8; 32],
            16,
            10,
            "small.bin".to_string(),
        ),
    )
    .await??;

    let big_econ = filestorage::get_agreement_economics(runtime, &big.agreement_id)
        .await?
        .expect("big economics present");
    let small_econ = filestorage::get_agreement_economics(runtime, &small.agreement_id)
        .await?
        .expect("small economics present");

    assert_eq!(big_econ.s_bytes, 1_000_000);
    assert_eq!(small_econ.s_bytes, 10);
    // rank_f = files_ever_created_at_creation + r_offset + 1; created back to
    // back, so small's rank is exactly one past big's.
    assert_eq!(big_econ.rank_f, 1001);
    assert_eq!(small_econ.rank_f, 1002);
    let zero: Decimal = 0u64.try_into().unwrap();
    assert!(big_econ.omega_f > zero);
    assert!(small_econ.omega_f > zero);
    assert!(big_econ.k_f > zero);
    // Larger file carries more emission weight despite its marginally lower rank.
    assert!(
        big_econ.omega_f > small_econ.omega_f,
        "larger file must have larger ω_f"
    );
    // Storage creation fee υ_f = χ_fee · k_f was charged from the creator and is
    // a small fraction of k_f (χ_fee = 0.3%).
    assert!(big.fee > zero, "storage creation fee charged");
    assert!(big.fee < big_econ.k_f, "fee is a fraction of k_f");
    assert!(small.fee > zero, "small file also charged a fee");

    // Creating (inactive) agreements must not move Ω or |F|.
    assert_eq!(filestorage::get_omega(runtime).await?, omega0);
    assert_eq!(filestorage::get_active_file_count(runtime).await?, files0);

    // Activate the big file: Ω grows by ω_f, |F| increments.
    let mut ops = Ops::new(&signer);
    ops.push(filestorage::join_agreement_call(&big.agreement_id, "n1"));
    ops.push(filestorage::join_agreement_call(&big.agreement_id, "n2"));
    ops.push(filestorage::join_agreement_call(&big.agreement_id, "n3"));
    let mut submit = runtime.submit();
    submit.add(ops);
    submit.execute().await?;

    assert_eq!(
        filestorage::get_active_file_count(runtime).await?,
        files0 + 1
    );
    let omega1 = filestorage::get_omega(runtime).await?;
    assert!(omega1 > omega0, "Ω must grow when a file activates");

    // Distribute a reward pool: one positive allocation per active node of the
    // big file, each strictly below the pool (genesis dilution + 3-way split).
    let pool: Decimal = 1_000_000u64.try_into().unwrap();
    let rewards = filestorage::distribute_storage_rewards(runtime, &core_signer, pool).await??;
    let big_rewards: Vec<_> = rewards
        .iter()
        .filter(|r| r.agreement_id == big.agreement_id)
        .collect();
    assert_eq!(big_rewards.len(), 3, "one allocation per active node");
    for r in &big_rewards {
        assert!(r.amount > zero, "reward must be positive");
        assert!(r.amount < pool, "a single node's share is below the pool");
    }

    // Admin can retune parameters.
    let new_params = filestorage::StorageParams {
        omega_genesis: 2000,
        r_offset: 500,
        c_stake: 3u64.try_into().unwrap(),
        f_scale: 7000,
        chi_fee_bps: 50,
    };
    filestorage::set_storage_params(runtime, &core_signer, new_params).await??;
    let got = filestorage::get_storage_params(runtime).await?;
    assert_eq!(got.omega_genesis, 2000);
    assert_eq!(got.r_offset, 500);
    assert_eq!(got.f_scale, 7000);
    assert_eq!(got.c_stake, 3u64.try_into().unwrap());
    assert_eq!(got.chi_fee_bps, 50);

    Ok(())
}

pub async fn run_core_signer_smoke(runtime: &mut Runtime) -> Result<()> {
    storage_economics_smoke(runtime).await?;
    challenge_gen_smoke_test(runtime).await
}

pub async fn run_core_signer_lucky(runtime: &mut Runtime) -> Result<()> {
    challenge_gen_with_lucky_hash(runtime).await
}
