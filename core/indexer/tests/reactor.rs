use anyhow::Result;
use indexer_types::Block;

use bitcoin::{BlockHash, hashes::Hash};

use indexer::{
    reactor,
    runtime::{Decimal, filestorage, token, wit::Signer},
    test_utils::make_descriptor,
};

#[tokio::test]
async fn test_reactor_generate_challenges_deterministic_no_challenge() -> Result<()> {
    let setup_block = Block {
        height: 0,
        hash: BlockHash::from_byte_array([0x00; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    let (mut runtime, _temp_dir) = testlib::Runtime::new_local_with_block(&setup_block).await?;

    let descriptor = make_descriptor(
        "reactor_lucky".to_string(),
        vec![1u8; 32],
        16,
        100,
        "reactor_lucky.txt".to_string(),
    );
    let core_signer = Signer::Core(Box::new(Signer::Nobody));
    token::api::issuance(&mut runtime, &core_signer, Decimal::from(100u64)).await??;

    let signer = Signer::Nobody;
    let created = filestorage::api::create_agreement(&mut runtime, &signer, descriptor).await??;
    let min_nodes = filestorage::api::get_min_nodes(&mut runtime).await?;
    for node_index in 0..min_nodes {
        let node_id = format!("node_{}", node_index);
        let node_signer = Signer::XOnlyPubKey(node_id.clone());
        runtime.issuance(&node_signer).await?;
        filestorage::api::join_agreement(
            &mut runtime,
            &node_signer,
            &created.agreement_id,
            &node_id,
        )
        .await??;
    }
    let agreement = filestorage::api::get_agreement(&mut runtime, &created.agreement_id)
        .await?
        .expect("agreement should exist");
    assert!(
        agreement.active,
        "agreement should be active before reactor block handling"
    );

    // Fixed inputs: for this block hash, the deterministic roll yields 0 challenges for a single
    // eligible agreement under the default parameters. This keeps the reactor test non-flaky.
    let block_height = 100001u64;
    let block = Block {
        height: block_height,
        hash: BlockHash::from_byte_array([0x01; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    reactor::block_handler(&mut runtime, &block).await?;

    let after = filestorage::api::get_active_challenges(&mut runtime).await?;
    assert_eq!(after.len(), 0, "fixed hash should generate no challenges");

    Ok(())
}
