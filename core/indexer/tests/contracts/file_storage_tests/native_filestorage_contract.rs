use indexer::test_utils::make_descriptor;
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

// Membership is keyed on the signer now, so each "node" is a distinct signer
// and its node_id is the signer's key (`signer.to_string()`). The join result
// echoes it back, which the tests assert to confirm the two agree.
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
    // min_nodes is the one protocol param the contract still owns (the rest moved
    // host-side with challenge generation).
    assert_eq!(filestorage::get_min_nodes(runtime).await?, 3);

    // Unknown IDs should be safe.
    assert!(
        filestorage::get_agreement(runtime, "nonexistent")
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
    let owner = runtime.identity().await?;

    // Create inactive agreement
    let a1 = filestorage::create_agreement(
        runtime,
        &owner,
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

    // Activate it by reaching min_nodes with three distinct signers.
    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;
    filestorage::join_agreement(runtime, &s1, &a1.agreement_id).await??;
    filestorage::join_agreement(runtime, &s2, &a1.agreement_id).await??;
    filestorage::join_agreement(runtime, &s3, &a1.agreement_id).await??;
    let active = filestorage::get_all_active_agreements(runtime).await?;
    assert!(
        active
            .iter()
            .any(|a| a.agreement_id == a1.agreement_id && a.active)
    );

    // A second agreement that stays inactive should not be returned.
    let a2 = filestorage::create_agreement(
        runtime,
        &owner,
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
// Node Join/Leave Tests (signer-keyed membership)
// ─────────────────────────────────────────────────────────────────

async fn filestorage_join_agreement(runtime: &mut Runtime) -> Result<()> {
    let owner = runtime.identity().await?;
    let descriptor = make_descriptor(
        "join_test".to_string(),
        vec![2u8; 32],
        16,
        10,
        "join.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &owner, descriptor).await??;

    let s1 = runtime.identity().await?;
    let node1 = s1.to_string();
    let result = filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    assert_eq!(result.agreement_id, created.agreement_id);
    assert_eq!(result.node_id, node1);
    assert!(!result.activated); // Not activated yet (need 3 nodes by default)

    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    assert!(!agreement.expect("agreement should exist").active);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 1);
    assert!(has_node(&nodes, &node1, true));

    Ok(())
}

async fn filestorage_join_activates_at_min_nodes(runtime: &mut Runtime) -> Result<()> {
    let owner = runtime.identity().await?;
    let descriptor = make_descriptor(
        "activate_test".to_string(),
        vec![3u8; 32],
        16,
        10,
        "activate.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &owner, descriptor).await??;

    assert_eq!(filestorage::get_min_nodes(runtime).await?, 3);

    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;

    assert!(
        !filestorage::join_agreement(runtime, &s1, &created.agreement_id)
            .await??
            .activated
    );
    assert!(
        !filestorage::join_agreement(runtime, &s2, &created.agreement_id)
            .await??
            .activated
    );
    assert!(
        filestorage::join_agreement(runtime, &s3, &created.agreement_id)
            .await??
            .activated // Third signer activates it
    );

    let agreement = filestorage::get_agreement(runtime, &created.agreement_id).await?;
    assert!(agreement.expect("agreement should exist").active);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 3);
    assert!(has_node(&nodes, &s1.to_string(), true));
    assert!(has_node(&nodes, &s2.to_string(), true));
    assert!(has_node(&nodes, &s3.to_string(), true));

    Ok(())
}

async fn filestorage_double_join_fails(runtime: &mut Runtime) -> Result<()> {
    let owner = runtime.identity().await?;
    let descriptor = make_descriptor(
        "double_join_test".to_string(),
        vec![4u8; 32],
        16,
        10,
        "double.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &owner, descriptor).await??;

    let s1 = runtime.identity().await?;
    filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;

    // Same signer joining again should fail (one slot per signer).
    let err = filestorage::join_agreement(runtime, &s1, &created.agreement_id).await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_join_nonexistent_agreement_fails(runtime: &mut Runtime) -> Result<()> {
    let s1 = runtime.identity().await?;
    let err = filestorage::join_agreement(runtime, &s1, "nonexistent").await?;
    assert!(matches!(err, Err(Error::Message(_))));
    Ok(())
}

async fn filestorage_leave_agreement(runtime: &mut Runtime) -> Result<()> {
    let owner = runtime.identity().await?;
    let descriptor = make_descriptor(
        "leave_test".to_string(),
        vec![5u8; 32],
        16,
        10,
        "leave.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &owner, descriptor).await??;

    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    filestorage::join_agreement(runtime, &s2, &created.agreement_id).await??;

    // s1 leaves its own slot.
    let result = filestorage::leave_agreement(runtime, &s1, &created.agreement_id).await??;
    assert_eq!(result.agreement_id, created.agreement_id);
    assert_eq!(result.node_id, s1.to_string());

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 2);
    assert!(has_node(&nodes, &s1.to_string(), false));
    assert!(has_node(&nodes, &s2.to_string(), true));

    Ok(())
}

async fn filestorage_leave_nonmember_fails(runtime: &mut Runtime) -> Result<()> {
    let owner = runtime.identity().await?;
    let descriptor = make_descriptor(
        "leave_nonmember_test".to_string(),
        vec![6u8; 32],
        16,
        10,
        "leave_nonmember.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &owner, descriptor).await??;

    // A signer that never joined can't leave.
    let s1 = runtime.identity().await?;
    let err = filestorage::leave_agreement(runtime, &s1, &created.agreement_id).await?;
    assert!(matches!(err, Err(Error::Message(_))));

    Ok(())
}

async fn filestorage_leave_nonexistent_agreement_fails(runtime: &mut Runtime) -> Result<()> {
    let s1 = runtime.identity().await?;
    let err = filestorage::leave_agreement(runtime, &s1, "nonexistent").await?;
    assert!(matches!(err, Err(Error::Message(_))));
    Ok(())
}

async fn filestorage_leave_does_not_deactivate(runtime: &mut Runtime) -> Result<()> {
    let owner = runtime.identity().await?;
    let descriptor = make_descriptor(
        "no_deactivate_test".to_string(),
        vec![7u8; 32],
        16,
        10,
        "no_deactivate.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &owner, descriptor).await??;

    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;
    filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    filestorage::join_agreement(runtime, &s2, &created.agreement_id).await??;
    filestorage::join_agreement(runtime, &s3, &created.agreement_id).await??;

    assert!(
        filestorage::get_agreement(runtime, &created.agreement_id)
            .await?
            .expect("exists")
            .active
    );

    // Two signers leave, dropping below min_nodes.
    filestorage::leave_agreement(runtime, &s1, &created.agreement_id).await??;
    filestorage::leave_agreement(runtime, &s2, &created.agreement_id).await??;

    // Agreement stays active (no deactivation on leave).
    assert!(
        filestorage::get_agreement(runtime, &created.agreement_id)
            .await?
            .expect("agreement should exist")
            .active
    );

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 3);
    assert!(has_node(&nodes, &s1.to_string(), false));
    assert!(has_node(&nodes, &s2.to_string(), false));
    assert!(has_node(&nodes, &s3.to_string(), true));

    Ok(())
}

async fn filestorage_is_node_in_agreement(runtime: &mut Runtime) -> Result<()> {
    let owner = runtime.identity().await?;
    let descriptor = make_descriptor(
        "is_node_test".to_string(),
        vec![8u8; 32],
        16,
        10,
        "is_node.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &owner, descriptor).await??;

    let s1 = runtime.identity().await?;
    let node1 = s1.to_string();

    assert!(!filestorage::is_node_in_agreement(runtime, &created.agreement_id, &node1).await?);

    let result = filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    assert_eq!(result.node_id, node1);
    assert!(filestorage::is_node_in_agreement(runtime, &created.agreement_id, &node1).await?);

    filestorage::leave_agreement(runtime, &s1, &created.agreement_id).await??;
    assert!(!filestorage::is_node_in_agreement(runtime, &created.agreement_id, &node1).await?);

    Ok(())
}

async fn filestorage_is_node_in_nonexistent_agreement(runtime: &mut Runtime) -> Result<()> {
    // Checking a nonexistent agreement should return false, not error.
    assert!(!filestorage::is_node_in_agreement(runtime, "nonexistent", "node_1").await?);
    Ok(())
}

async fn filestorage_rejoin_after_leave(runtime: &mut Runtime) -> Result<()> {
    let owner = runtime.identity().await?;
    let descriptor = make_descriptor(
        "rejoin_test".to_string(),
        vec![9u8; 32],
        16,
        10,
        "rejoin.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &owner, descriptor).await??;

    let s1 = runtime.identity().await?;
    let node1 = s1.to_string();
    filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    assert!(filestorage::is_node_in_agreement(runtime, &created.agreement_id, &node1).await?);

    filestorage::leave_agreement(runtime, &s1, &created.agreement_id).await??;
    assert!(!filestorage::is_node_in_agreement(runtime, &created.agreement_id, &node1).await?);

    // Rejoin should succeed.
    let result = filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    assert_eq!(result.node_id, node1);
    assert!(filestorage::is_node_in_agreement(runtime, &created.agreement_id, &node1).await?);

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 1);

    Ok(())
}

async fn filestorage_join_after_activation_not_reactivated(runtime: &mut Runtime) -> Result<()> {
    let owner = runtime.identity().await?;
    let descriptor = make_descriptor(
        "no_reactivate_test".to_string(),
        vec![10u8; 32],
        16,
        10,
        "no_reactivate.txt".to_string(),
    );
    let created = filestorage::create_agreement(runtime, &owner, descriptor).await??;

    let s1 = runtime.identity().await?;
    let s2 = runtime.identity().await?;
    let s3 = runtime.identity().await?;
    let s4 = runtime.identity().await?;
    filestorage::join_agreement(runtime, &s1, &created.agreement_id).await??;
    filestorage::join_agreement(runtime, &s2, &created.agreement_id).await??;
    assert!(
        filestorage::join_agreement(runtime, &s3, &created.agreement_id)
            .await??
            .activated // Third signer activates
    );

    // Fourth join should not report activated (already active).
    assert!(
        !filestorage::join_agreement(runtime, &s4, &created.agreement_id)
            .await??
            .activated
    );

    assert!(
        filestorage::get_agreement(runtime, &created.agreement_id)
            .await?
            .expect("exists")
            .active
    );

    let nodes = filestorage::get_agreement_nodes(runtime, &created.agreement_id).await?;
    assert_eq!(nodes.len(), 4);

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
