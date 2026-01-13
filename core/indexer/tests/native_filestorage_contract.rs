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

fn make_descriptor(
    file_id: String,
    root: Vec<u8>,
    padded_len: u64,
    original_size: u64,
    filename: String,
) -> RawFileDescriptor {
    RawFileDescriptor {
        file_id,
        root,
        padded_len,
        original_size,
        filename,
    }
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

    // With no generated challenges, this should be empty.
    let active = filestorage::get_active_challenges(runtime).await?;
    assert!(active.is_empty());

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
    filestorage::join_agreement(runtime, &signer, &a1.agreement_id, "node_1").await??;
    filestorage::join_agreement(runtime, &signer, &a1.agreement_id, "node_2").await??;
    filestorage::join_agreement(runtime, &signer, &a1.agreement_id, "node_3").await??;
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

async fn filestorage_expire_challenges_noop(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    filestorage::expire_challenges(runtime, &signer, 0).await?;
    filestorage::expire_challenges(runtime, &signer, 1_000_000).await?;
    let active = filestorage::get_active_challenges(runtime).await?;
    assert!(active.is_empty());
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

    // Create agreement and join
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_2").await??;

    // Leave with node_1
    let result =
        filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    assert_eq!(result.agreement_id, created.agreement_id);
    assert_eq!(result.node_id, "node_1");

    // Verify node is removed
    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 2);
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

async fn filestorage_leave_does_not_deactivate(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor(
        "no_deactivate_test".to_string(),
        vec![7u8; 32],
        16,
        10,
        "no_deactivate.txt".to_string(),
    );

    // Create agreement and activate it
    let created = filestorage::create_agreement(runtime, &signer, descriptor).await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_2").await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_3").await??;

    // Verify active
    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    assert!(agreement.expect("exists").active);

    // Leave nodes until below min_nodes
    filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    filestorage::leave_agreement(runtime, &signer, &created.agreement_id, "node_2").await??;

    // Agreement should still be active (no deactivation)
    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    let agreement = agreement.expect("agreement should exist");
    assert!(agreement.active); // Still active!

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 3);
    assert!(has_node(&nodes, "node_1", false));
    assert!(has_node(&nodes, "node_2", false));
    assert!(has_node(&nodes, "node_3", true));

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
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_2").await??;
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
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_0").await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_1").await??;
    filestorage::join_agreement(runtime, &signer, &created.agreement_id, "node_2").await??;

    let block_hash = vec![1u8; 32];
    let challenges =
        filestorage::generate_challenges_for_block(runtime, &signer, 1000, block_hash).await?;

    // Verify the return type is correct (list of challenges, possibly empty)
    assert!(challenges.len() <= 1, "Should have 0 or 1 challenges");

    // Verify get_active_challenges works
    let active = filestorage::get_active_challenges(runtime).await?;
    assert_eq!(active.len(), challenges.len());

    // Verify expire_challenges works
    filestorage::expire_challenges(runtime, &signer, 10000).await?;

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_create_and_get() -> Result<()> {
    filestorage_defaults(runtime).await?;
    filestorage_empty_file_id_fails(runtime).await?;
    filestorage_get_all_active_agreements(runtime).await?;
    filestorage_expire_challenges_noop(runtime).await?;
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
    challenge_gen_smoke_test(runtime).await?;
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_create_and_get_regtest() -> Result<()> {
    filestorage_defaults(runtime).await?;
    filestorage_empty_file_id_fails(runtime).await?;
    filestorage_get_all_active_agreements(runtime).await?;
    filestorage_expire_challenges_noop(runtime).await?;
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
    challenge_gen_smoke_test(runtime).await?;
    Ok(())
}
