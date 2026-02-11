use anyhow::Result;
use indexer_types::{Block, Op, OpMetadata, Transaction};
use indexmap::IndexMap;
use tokio_util::sync::CancellationToken;

use bitcoin::{BlockHash, hashes::Hash};

use indexer::{
    bitcoin_follower::{
        ctrl::CtrlChannel,
        events::{BlockId, Event},
    },
    database::queries,
    reactor,
    runtime::{Decimal, filestorage, token, wit::Signer},
    test_utils::{
        LUCKY_HASH_100000, await_block_at_height, lucky_hash, make_descriptor,
        new_numbered_blockchain, new_test_db,
    },
};

#[tokio::test]
async fn test_reactor_rollback_event() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let handle = reactor::run(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
        None,
        None,
        None,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 91);
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 91,
                hash: BlockHash::from_byte_array([0x10; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x20; 32]),
                prev_hash: BlockHash::from_byte_array([0x10; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x30; 32]),
                prev_hash: BlockHash::from_byte_array([0x20; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    let conn = &*reader.connection().await?;
    let block = await_block_at_height(conn, 92).await;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x20; 32]));

    assert!(
        tx.send(Event::BlockRemove(BlockId::Height(91)))
            .await
            .is_ok()
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 92);
    assert_eq!(
        start.last_hash,
        Some(BlockHash::from_byte_array([0x10; 32]))
    );
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x21; 32]),
                prev_hash: BlockHash::from_byte_array([0x10; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x31; 32]),
                prev_hash: BlockHash::from_byte_array([0x21; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    let block = await_block_at_height(conn, 92).await;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x21; 32]));

    let block = await_block_at_height(conn, 93).await;
    assert_eq!(block.height, 93);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x31; 32]));

    assert!(!handle.is_finished());

    cancel_token.cancel();
    let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_unexpected_block() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let handle = reactor::run(
        81,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
        None,
        None,
        None,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 81);
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 82, // skipping 81
                hash: BlockHash::from_byte_array([0x01; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    cancel_token.cancelled().await;
    assert!(cancel_token.is_cancelled());

    let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_due_to_hash_mismatch() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let handle = reactor::run(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
        None,
        None,
        None,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 91);
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 91,
                hash: BlockHash::from_byte_array([0x01; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x02; 32]),
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    let conn = &*reader.connection().await?;
    let block = await_block_at_height(conn, 92).await;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x02; 32]));

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x03; 32]),
                prev_hash: BlockHash::from_byte_array([0x12; 32]), // not matching
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 92);
    assert_eq!(
        start.last_hash,
        Some(BlockHash::from_byte_array([0x01; 32]))
    );

    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x12; 32]),
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    let block = await_block_at_height(conn, 92).await;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x12; 32]));

    assert!(!handle.is_finished());

    cancel_token.cancel();
    let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_due_to_reverting_height() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let handle = reactor::run(
        91,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
        None,
        None,
        None,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 91);
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 91,
                hash: BlockHash::from_byte_array([0x01; 32]),
                prev_hash: BlockHash::from_byte_array([0x00; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x02; 32]),
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 93,
                hash: BlockHash::from_byte_array([0x03; 32]),
                prev_hash: BlockHash::from_byte_array([0x02; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,                                   // lower height
                hash: BlockHash::from_byte_array([0x12; 32]), // new hash
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    // we're re-requesting the block we just received, which is wasteful but
    // it doesn't seem worth having a special code-path for what should be
    // an exceptional case.

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 92);
    assert_eq!(
        start.last_hash,
        Some(BlockHash::from_byte_array([0x01; 32]))
    );
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockInsert((
            100,
            Block {
                height: 92,
                hash: BlockHash::from_byte_array([0x12; 32]),
                prev_hash: BlockHash::from_byte_array([0x01; 32]),
                transactions: vec![],
            },
        )))
        .await
        .is_ok()
    );

    let conn = &*reader.connection().await?;
    let block = await_block_at_height(conn, 92).await;
    assert_eq!(block.height, 92);
    assert_eq!(block.hash, BlockHash::from_byte_array([0x12; 32]));

    assert!(!handle.is_finished());

    cancel_token.cancel();
    let _ = handle.await;

    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_hash_event() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (ctrl, mut ctrl_rx) = CtrlChannel::create();
    let (reader, writer, _temp_dir) = new_test_db().await?;

    let blocks = new_numbered_blockchain(5);
    let conn = &writer.connection();
    queries::insert_processed_block(conn, (&blocks[1 - 1]).into()).await?;
    queries::insert_processed_block(conn, (&blocks[2 - 1]).into()).await?;
    queries::insert_processed_block(conn, (&blocks[3 - 1]).into()).await?;

    let handle = reactor::run(
        4,
        cancel_token.clone(),
        reader.clone(),
        writer.clone(),
        ctrl,
        None,
        None,
        None,
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 4);
    assert_eq!(start.last_hash, Some(blocks[3 - 1].hash));
    let tx = start.event_tx;

    assert!(
        tx.send(Event::BlockRemove(BlockId::Hash(blocks[2 - 1].hash)))
            .await
            .is_ok()
    );

    let start = ctrl_rx.recv().await.unwrap();
    assert_eq!(start.start_height, 2);
    assert_eq!(start.last_hash, Some(blocks[1 - 1].hash));
    assert!(!handle.is_finished());
    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn test_reactor_generate_challenges_with_lucky_hash() -> Result<()> {
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
        filestorage::api::join_agreement(&mut runtime, &signer, &created.agreement_id, &node_id)
            .await??;
    }

    let block_height = 100000u64;
    let block = Block {
        height: block_height,
        hash: BlockHash::from_byte_array(lucky_hash(LUCKY_HASH_100000)),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    reactor::block_handler(&mut runtime, &block).await?;

    let after = filestorage::api::get_active_challenges(&mut runtime).await?;
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].agreement_id, created.agreement_id);
    assert_eq!(after[0].block_height, block_height);

    Ok(())
}

#[tokio::test]
async fn test_reactor_first_class_filestorage_ops() -> Result<()> {
    let setup_block = Block {
        height: 0,
        hash: BlockHash::from_byte_array([0x00; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    let (mut runtime, _temp_dir) = testlib::Runtime::new_local_with_block(&setup_block).await?;
    let core_signer = Signer::Core(Box::new(Signer::Nobody));
    token::api::issuance(&mut runtime, &core_signer, Decimal::from(100u64)).await??;

    let file_metadata = indexer_types::FileMetadata {
        root: vec![42u8; 32],
        object_id: "obj_reactor_test".to_string(),
        file_id: "file_reactor_test".to_string(),
        nonce: vec![42u8; 32],
        padded_len: 16,
        original_size: 15,
        filename: "reactor-op-test.txt".to_string(),
    };
    let agreement_id = file_metadata.file_id.clone();

    let create_block = Block {
        height: 1,
        hash: BlockHash::from_byte_array([0x01; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![Transaction {
            txid: bitcoin::Txid::from_byte_array([0x11; 32]),
            index: 0,
            ops: vec![Op::CreateAgreement {
                metadata: OpMetadata {
                    previous_output: bitcoin::OutPoint {
                        txid: bitcoin::Txid::from_byte_array([0x21; 32]),
                        vout: 0,
                    },
                    input_index: 0,
                    signer: Signer::Nobody,
                },
                file_metadata,
            }],
            op_return_data: IndexMap::new(),
        }],
    };
    reactor::block_handler(&mut runtime, &create_block).await?;
    let created = filestorage::api::get_agreement(&mut runtime, &agreement_id).await?;
    assert!(created.is_some());
    assert!(!created.expect("agreement must exist").active);

    let join_block = Block {
        height: 2,
        hash: BlockHash::from_byte_array([0x02; 32]),
        prev_hash: BlockHash::from_byte_array([0x01; 32]),
        transactions: vec![Transaction {
            txid: bitcoin::Txid::from_byte_array([0x12; 32]),
            index: 0,
            ops: vec![
                Op::JoinAgreement {
                    metadata: OpMetadata {
                        previous_output: bitcoin::OutPoint {
                            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
                            vout: 0,
                        },
                        input_index: 0,
                        signer: Signer::Nobody,
                    },
                    agreement_id: agreement_id.clone(),
                    node_id: "node_1".to_string(),
                },
                Op::JoinAgreement {
                    metadata: OpMetadata {
                        previous_output: bitcoin::OutPoint {
                            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
                            vout: 1,
                        },
                        input_index: 1,
                        signer: Signer::Nobody,
                    },
                    agreement_id: agreement_id.clone(),
                    node_id: "node_2".to_string(),
                },
                Op::JoinAgreement {
                    metadata: OpMetadata {
                        previous_output: bitcoin::OutPoint {
                            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
                            vout: 2,
                        },
                        input_index: 2,
                        signer: Signer::Nobody,
                    },
                    agreement_id: agreement_id.clone(),
                    node_id: "node_3".to_string(),
                },
            ],
            op_return_data: IndexMap::new(),
        }],
    };
    reactor::block_handler(&mut runtime, &join_block).await?;
    let after_join = filestorage::api::get_agreement(&mut runtime, &agreement_id).await?;
    assert!(after_join.expect("agreement must exist").active);

    let leave_block = Block {
        height: 3,
        hash: BlockHash::from_byte_array([0x03; 32]),
        prev_hash: BlockHash::from_byte_array([0x02; 32]),
        transactions: vec![Transaction {
            txid: bitcoin::Txid::from_byte_array([0x13; 32]),
            index: 0,
            ops: vec![Op::LeaveAgreement {
                metadata: OpMetadata {
                    previous_output: bitcoin::OutPoint {
                        txid: bitcoin::Txid::from_byte_array([0x23; 32]),
                        vout: 0,
                    },
                    input_index: 0,
                    signer: Signer::Nobody,
                },
                agreement_id: agreement_id.clone(),
                node_id: "node_1".to_string(),
            }],
            op_return_data: IndexMap::new(),
        }],
    };
    reactor::block_handler(&mut runtime, &leave_block).await?;
    let nodes = filestorage::api::get_agreement_nodes(&mut runtime, &agreement_id).await?;
    assert!(nodes.iter().any(|n| n.node_id == "node_1" && !n.active));

    Ok(())
}
