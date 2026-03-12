use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Network, OutPoint, Txid};
use indexmap::IndexMap;
use libsql::params;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

use indexer::{
    bitcoin_follower::event::BitcoinEvent,
    bls::{
        KONTOR_BLS_DST, RegistrationProof, bls_derivation_path, derive_bls_secret_key_eip2333,
        taproot_derivation_path,
    },
    database::queries,
    reactor,
    reg_tester::derive_taproot_keypair_from_seed,
    test_utils::{gen_random_blocks, new_mock_block_hash, new_random_blockchain, new_test_db},
};
use indexer_types::{BlsBulkOp, Event, Op, OpMetadata, Signer, Transaction};

/// Poll until a processed block at `height` has the expected `hash`.
async fn await_block_hash(conn: &libsql::Connection, height: i64, hash: BlockHash) {
    loop {
        if let Ok(Some(block)) = queries::select_processed_block_at_height(conn, height).await
            && block.hash == hash
        {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn send_block_and_wait(
    tx: &mpsc::Sender<BitcoinEvent>,
    conn: &libsql::Connection,
    block: &indexer_types::Block,
    target_height: u64,
) {
    let hash = block.hash;
    let height = block.height as i64;
    tx.send(BitcoinEvent::BlockInsert {
        target_height,
        block: block.clone(),
    })
    .await
    .unwrap();
    await_block_hash(conn, height, hash).await;
}

#[tokio::test]
async fn test_reactor_fetching() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let blocks = new_random_blockchain(5);

    let (event_tx, event_rx) = mpsc::channel(10);
    let handle = reactor::run(1, cancel_token.clone(), writer, event_rx, None, None, None);

    let target = 5;
    for block in &blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    for (i, expected) in blocks.iter().enumerate() {
        let block = queries::select_processed_block_at_height(conn, (i + 1) as i64)
            .await?
            .unwrap();
        assert_eq!(block.hash, expected.hash);
    }

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_and_reinsert() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let blocks = new_random_blockchain(3);

    let (event_tx, event_rx) = mpsc::channel(10);
    let handle = reactor::run(1, cancel_token.clone(), writer, event_rx, None, None, None);

    // Insert blocks 1-3
    let target = 3;
    for block in &blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    let initial_block_3_hash = blocks[2].hash;

    // Rollback to height 2 (remove block 3), then insert new blocks 3-5
    event_tx
        .send(BitcoinEvent::Rollback { to_height: 2 })
        .await?;

    let new_blocks = gen_random_blocks(2, 5, Some(blocks[1].hash));
    let target = 5;
    for block in &new_blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Block 3 should have a different hash now
    let block = queries::select_processed_block_at_height(conn, 3)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[0].hash);
    assert_ne!(block.hash, initial_block_3_hash);

    // Blocks 4-5 should exist with new hashes
    let block = queries::select_processed_block_at_height(conn, 5)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[2].hash);

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn test_reactor_deep_rollback() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let blocks = new_random_blockchain(4);

    let (event_tx, event_rx) = mpsc::channel(10);
    let handle = reactor::run(1, cancel_token.clone(), writer, event_rx, None, None, None);

    // Insert blocks 1-4
    let target = 4;
    for block in &blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Roll back to height 1 (remove blocks 2-4)
    event_tx
        .send(BitcoinEvent::Rollback { to_height: 1 })
        .await?;

    // Insert new chain from block 1
    let new_blocks = gen_random_blocks(1, 4, Some(blocks[0].hash));
    let target = 4;
    for block in &new_blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Block 1 should be preserved
    let block = queries::select_processed_block_at_height(conn, 1)
        .await?
        .unwrap();
    assert_eq!(block.hash, blocks[0].hash);

    // Block 2 should have new hash
    let block = queries::select_processed_block_at_height(conn, 2)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[0].hash);

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn test_reactor_rollback_then_extend() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let blocks = new_random_blockchain(2);

    let (event_tx, event_rx) = mpsc::channel(10);
    let handle = reactor::run(1, cancel_token.clone(), writer, event_rx, None, None, None);

    // Insert blocks 1-2
    let target = 2;
    for block in &blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Extend with blocks 3-4
    let more_blocks = gen_random_blocks(2, 4, Some(blocks[1].hash));
    let target = 4;
    for block in &more_blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    let block = queries::select_processed_block_at_height(conn, 4)
        .await?
        .unwrap();
    assert_eq!(block.hash, more_blocks[1].hash);

    // Roll back to height 1, insert entirely new chain
    event_tx
        .send(BitcoinEvent::Rollback { to_height: 1 })
        .await?;

    let new_blocks = gen_random_blocks(1, 4, Some(blocks[0].hash));
    let target = 4;
    for block in &new_blocks {
        send_block_and_wait(&event_tx, conn, block, target).await;
    }

    // Verify block 2 has new hash
    let block = queries::select_processed_block_at_height(conn, 2)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[0].hash);

    // Verify block 4 has new hash
    let block = queries::select_processed_block_at_height(conn, 4)
        .await?
        .unwrap();
    assert_eq!(block.hash, new_blocks[2].hash);

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

/// Sends a block through the reactor's event channel and waits for the
/// `Event::Processed` acknowledgement on the output channel. Unlike the
/// DB-polling `send_block_and_wait`, this uses the reactor's own event
/// stream so we know the block has been fully processed (including all
/// WASM contract execution) before continuing.
async fn send_block_and_await_event(
    event_tx: &mpsc::Sender<BitcoinEvent>,
    output_rx: &mut mpsc::Receiver<Event>,
    block: indexer_types::Block,
    target_height: u64,
) {
    let expected_height = block.height as i64;
    event_tx
        .send(BitcoinEvent::BlockInsert {
            target_height,
            block,
        })
        .await
        .unwrap();
    match output_rx.recv().await.unwrap() {
        Event::Processed { block } => assert_eq!(block.height, expected_height),
        other => panic!("expected Processed at height {expected_height}, got {other:?}"),
    }
}

/// Proves that rolling back a block containing a BLS key registration
/// reverts the registry contract_state created by that registration.
///
/// This exercises the full pipeline: reactor → block_handler →
/// process_transaction → WASM runtime (registry contract execution) →
/// contract_state write, then rollback → CASCADE delete → state gone.
#[tokio::test]
async fn test_reactor_rollback_reverts_registration_state() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let (event_tx, event_rx) = mpsc::channel(10);
    let (output_tx, mut output_rx) = mpsc::channel(10);
    let handle = reactor::run(
        1,
        cancel_token.clone(),
        writer,
        event_rx,
        None,
        Some(output_tx),
        None,
    );

    let seed = [42u8; 64];
    let keypair =
        derive_taproot_keypair_from_seed(&seed, &taproot_derivation_path(Network::Regtest))?;
    let (x_only_public_key, _) = keypair.x_only_public_key();
    let bls_sk =
        derive_bls_secret_key_eip2333(&seed, &bls_derivation_path(Network::Regtest))?;
    let proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes())?;

    let block1_hash = new_mock_block_hash(11);
    let block1 = indexer_types::Block {
        height: 1,
        hash: block1_hash,
        prev_hash: new_mock_block_hash(0),
        transactions: vec![Transaction {
            txid: Txid::from_slice(&[0xAA; 32]).unwrap(),
            index: 0,
            ops: vec![Op::RegisterBlsKey {
                metadata: OpMetadata {
                    previous_output: OutPoint::null(),
                    input_index: 0,
                    signer: Signer::XOnlyPubKey(x_only_public_key.to_string()),
                },
                bls_pubkey: proof.bls_pubkey.to_vec(),
                schnorr_sig: proof.schnorr_sig.to_vec(),
                bls_sig: proof.bls_sig.to_vec(),
            }],
            op_return_data: IndexMap::new(),
        }],
    };
    send_block_and_await_event(&event_tx, &mut output_rx, block1, 2).await;

    let state_count: u64 = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE height = 1",
            params![],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert!(
        state_count > 0,
        "registration must write contract_state at height 1"
    );

    event_tx
        .send(BitcoinEvent::Rollback { to_height: 0 })
        .await?;
    match output_rx.recv().await.unwrap() {
        Event::Rolledback { height } => assert_eq!(height, 0),
        other => panic!("expected Rolledback, got {other:?}"),
    }

    let state_count_after: u64 = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE height = 1",
            params![],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert_eq!(
        state_count_after, 0,
        "rollback must remove all contract_state from deleted block"
    );

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}

/// End-to-end nonce rollback: register a key (nonce=0 at height 1),
/// advance the nonce via BlsBulk (nonce→1 at height 2), roll back
/// height 2, and verify the nonce reverts to 0.
#[tokio::test]
async fn test_reactor_rollback_reverts_nonce_advance() -> Result<()> {
    let cancel_token = CancellationToken::new();
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = &writer.connection();

    let (event_tx, event_rx) = mpsc::channel(10);
    let (output_tx, mut output_rx) = mpsc::channel(10);
    let handle = reactor::run(
        1,
        cancel_token.clone(),
        writer,
        event_rx,
        None,
        Some(output_tx),
        None,
    );

    let seed = [42u8; 64];
    let keypair =
        derive_taproot_keypair_from_seed(&seed, &taproot_derivation_path(Network::Regtest))?;
    let (x_only_public_key, _) = keypair.x_only_public_key();
    let bls_sk =
        derive_bls_secret_key_eip2333(&seed, &bls_derivation_path(Network::Regtest))?;
    let proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes())?;

    // -- Block 1: register the BLS key (creates signer_id=0, next_nonce=0) --
    let block1_hash = new_mock_block_hash(11);
    let block1 = indexer_types::Block {
        height: 1,
        hash: block1_hash,
        prev_hash: new_mock_block_hash(0),
        transactions: vec![Transaction {
            txid: Txid::from_slice(&[0xAA; 32]).unwrap(),
            index: 0,
            ops: vec![Op::RegisterBlsKey {
                metadata: OpMetadata {
                    previous_output: OutPoint::null(),
                    input_index: 0,
                    signer: Signer::XOnlyPubKey(x_only_public_key.to_string()),
                },
                bls_pubkey: proof.bls_pubkey.to_vec(),
                schnorr_sig: proof.schnorr_sig.to_vec(),
                bls_sig: proof.bls_sig.to_vec(),
            }],
            op_return_data: IndexMap::new(),
        }],
    };
    send_block_and_await_event(&event_tx, &mut output_rx, block1, 3).await;

    let state_at_h1: u64 = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE height = 1",
            params![],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert!(state_at_h1 > 0, "registration must write state at height 1");

    // -- Block 2: BlsBulk Call that advances the nonce --
    let call_op = BlsBulkOp::Call {
        signer_id: 0,
        nonce: 0,
        gas_limit: 100_000,
        contract: indexer_types::ContractAddress {
            name: "registry".to_string(),
            height: 0,
            tx_index: 0,
        },
        expr: "get-signer-count()".to_string(),
    };
    let msg = call_op.signing_message()?;
    let sk = blst::min_sig::SecretKey::from_bytes(&bls_sk.to_bytes()).unwrap();
    let sig = sk.sign(&msg, KONTOR_BLS_DST, &[]);

    let block2_hash = new_mock_block_hash(22);
    let block2 = indexer_types::Block {
        height: 2,
        hash: block2_hash,
        prev_hash: block1_hash,
        transactions: vec![Transaction {
            txid: Txid::from_slice(&[0xBB; 32]).unwrap(),
            index: 0,
            ops: vec![Op::BlsBulk {
                metadata: OpMetadata {
                    previous_output: OutPoint::null(),
                    input_index: 0,
                    signer: Signer::Nobody,
                },
                ops: vec![call_op],
                signature: sig.to_bytes().to_vec(),
            }],
            op_return_data: IndexMap::new(),
        }],
    };
    send_block_and_await_event(&event_tx, &mut output_rx, block2, 3).await;

    let state_at_h2: u64 = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE height = 2",
            params![],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert!(
        state_at_h2 > 0,
        "nonce advance must write contract_state at height 2"
    );

    // -- Rollback to height 1: block 2 is deleted, nonce reverts --
    event_tx
        .send(BitcoinEvent::Rollback { to_height: 1 })
        .await?;
    match output_rx.recv().await.unwrap() {
        Event::Rolledback { height } => assert_eq!(height, 1),
        other => panic!("expected Rolledback, got {other:?}"),
    }

    let state_at_h2_after: u64 = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE height = 2",
            params![],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert_eq!(
        state_at_h2_after, 0,
        "rollback must remove all contract_state from height 2 (including nonce advance)"
    );

    let state_at_h1_after: u64 = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE height = 1",
            params![],
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get(0)?;
    assert!(
        state_at_h1_after > 0,
        "registration state at height 1 must survive rollback to height 1"
    );

    cancel_token.cancel();
    let _ = handle.await;
    Ok(())
}
