#![cfg(feature = "protocol-qualification")]

use anyhow::Result;
use indexer::protocol_qualification::{
    certified_branch_index_transitions, certified_decision_callbacks,
};

#[tokio::test]
async fn certified_branch_preserves_historical_anchors_and_parent_boundary() -> Result<()> {
    certified_branch_index_transitions().await
}

#[tokio::test]
async fn decision_ack_and_finalization_use_durable_exact_inputs() -> Result<()> {
    let evidence = certified_decision_callbacks().await?;
    assert_eq!(evidence["authenticated"], 3);
    assert_eq!(evidence["closed"], 3);
    assert_eq!(evidence["owned_block_stage"], true);
    assert_eq!(evidence["closure_publication_atomic"], true);
    assert_eq!(evidence["next_height_after_closure"], true);
    Ok(())
}
