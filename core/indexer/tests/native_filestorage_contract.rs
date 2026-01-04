use testlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/filestorage/wit",
);

fn make_descriptor(file_id: String, root: Vec<u8>, depth: u64) -> RawFileDescriptor {
    RawFileDescriptor {
        file_id,
        root,
        depth,
    }
}

async fn prepare_real_descriptor() -> Result<RawFileDescriptor> {
    let root: Vec<u8> = [0u8; 32].to_vec();
    let depth: u64 = 4;
    Ok(make_descriptor("test_file".to_string(), root, depth))
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
    assert_eq!(got.root, descriptor.root);
    assert_eq!(got.depth, descriptor.depth);
    assert!(!got.active);

    // Check nodes via separate function
    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert!(nodes.expect("should exist").is_empty());
    Ok(())
}

async fn filestorage_count_increments(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;

    let c0 = filestorage::agreement_count(runtime).await?;
    let d1 = prepare_real_descriptor().await?;
    filestorage::create_agreement(runtime, &signer, d1).await??;
    let c1 = filestorage::agreement_count(runtime).await?;
    assert_eq!(c1, c0 + 1);

    let d2 = make_descriptor("another_file".to_string(), vec![7u8; 32], 8);
    filestorage::create_agreement(runtime, &signer, d2).await??;
    let c2 = filestorage::agreement_count(runtime).await?;
    assert_eq!(c2, c1 + 1);

    Ok(())
}

async fn filestorage_duplicate_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor("dup_file".to_string(), vec![1u8; 32], 8);

    filestorage::create_agreement(runtime, &signer, descriptor.clone()).await??;
    let err = filestorage::create_agreement(runtime, &signer, descriptor).await?;
    assert!(matches!(err, Err(Error::Message(_))));
    Ok(())
}

async fn filestorage_invalid_root_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor("bad_root".to_string(), vec![1u8; 31], 8);

    let err = filestorage::create_agreement(runtime, &signer, descriptor).await?;
    assert!(matches!(err, Err(Error::Validation(_))));
    Ok(())
}

async fn filestorage_zero_depth_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor("zero_depth".to_string(), vec![1u8; 32], 0);

    let err = filestorage::create_agreement(runtime, &signer, descriptor).await?;
    assert!(matches!(err, Err(Error::Message(_))));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Node Join/Leave Tests
// ─────────────────────────────────────────────────────────────────

async fn filestorage_join_agreement(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor("join_test".to_string(), vec![2u8; 32], 4);

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
    let nodes = nodes.expect("should exist");
    assert_eq!(nodes.len(), 1);
    assert!(nodes.contains(&"node_1".to_string()));

    Ok(())
}

async fn filestorage_join_activates_at_min_nodes(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor("activate_test".to_string(), vec![3u8; 32], 4);

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
    assert_eq!(nodes.expect("should exist").len(), 3);

    Ok(())
}

async fn filestorage_double_join_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor("double_join_test".to_string(), vec![4u8; 32], 4);

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
    let descriptor = make_descriptor("leave_test".to_string(), vec![5u8; 32], 4);

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
    let nodes = nodes.expect("should exist");
    assert_eq!(nodes.len(), 1);
    assert!(!nodes.contains(&"node_1".to_string()));
    assert!(nodes.contains(&"node_2".to_string()));

    Ok(())
}

async fn filestorage_leave_nonmember_fails(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor("leave_nonmember_test".to_string(), vec![6u8; 32], 4);

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
    let descriptor = make_descriptor("no_deactivate_test".to_string(), vec![7u8; 32], 4);

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
    assert_eq!(nodes.expect("should exist").len(), 1);

    Ok(())
}

async fn filestorage_is_node_in_agreement(runtime: &mut Runtime) -> Result<()> {
    let signer = runtime.identity().await?;
    let descriptor = make_descriptor("is_node_test".to_string(), vec![8u8; 32], 4);

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

// ─────────────────────────────────────────────────────────────────
// Test Registration
// ─────────────────────────────────────────────────────────────────

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_create_and_get() -> Result<()> {
    filestorage_create_and_get(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_count_increments() -> Result<()> {
    filestorage_count_increments(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_duplicate_fails() -> Result<()> {
    filestorage_duplicate_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_invalid_root_fails() -> Result<()> {
    filestorage_invalid_root_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_zero_depth_fails() -> Result<()> {
    filestorage_zero_depth_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_join_agreement() -> Result<()> {
    filestorage_join_agreement(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_join_activates_at_min_nodes() -> Result<()> {
    filestorage_join_activates_at_min_nodes(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_double_join_fails() -> Result<()> {
    filestorage_double_join_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_join_nonexistent_agreement_fails() -> Result<()> {
    filestorage_join_nonexistent_agreement_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_leave_agreement() -> Result<()> {
    filestorage_leave_agreement(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_leave_nonmember_fails() -> Result<()> {
    filestorage_leave_nonmember_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_leave_nonexistent_agreement_fails() -> Result<()> {
    filestorage_leave_nonexistent_agreement_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_leave_does_not_deactivate() -> Result<()> {
    filestorage_leave_does_not_deactivate(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_filestorage_is_node_in_agreement() -> Result<()> {
    filestorage_is_node_in_agreement(runtime).await
}

// ─────────────────────────────────────────────────────────────────
// Regtest Tests
// ─────────────────────────────────────────────────────────────────

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_create_and_get_regtest() -> Result<()> {
    filestorage_create_and_get(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_count_increments_regtest() -> Result<()> {
    filestorage_count_increments(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_duplicate_fails_regtest() -> Result<()> {
    filestorage_duplicate_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_invalid_root_fails_regtest() -> Result<()> {
    filestorage_invalid_root_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_zero_depth_fails_regtest() -> Result<()> {
    filestorage_zero_depth_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_join_agreement_regtest() -> Result<()> {
    filestorage_join_agreement(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_join_activates_at_min_nodes_regtest() -> Result<()> {
    filestorage_join_activates_at_min_nodes(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_double_join_fails_regtest() -> Result<()> {
    filestorage_double_join_fails(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_leave_agreement_regtest() -> Result<()> {
    filestorage_leave_agreement(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_leave_does_not_deactivate_regtest() -> Result<()> {
    filestorage_leave_does_not_deactivate(runtime).await
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_filestorage_is_node_in_agreement_regtest() -> Result<()> {
    filestorage_is_node_in_agreement(runtime).await
}
