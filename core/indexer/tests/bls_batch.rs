use anyhow::Result;
use bitcoin::{BlockHash, OutPoint, Txid, hashes::Hash};
use blst::min_sig::{
    AggregateSignature, PublicKey as BlsPublicKey, SecretKey, Signature as BlsSignature,
};
use indexer::bls_batch::{BinaryCallV1, PROTOCOL_BLS_DST, SignerRef, op_message, pop_message};
use indexer::database::queries::{
    rollback_to_height, select_signer_registry_by_bls_pubkey, signer_nonce_exists,
};
use indexer::reactor;
use indexer_types::{Block, ContractAddress, Op, OpMetadata, Signer, Transaction};
use indexmap::IndexMap;
use std::io::Cursor;
use testlib::Runtime;

fn build_signed_kbl1_payload_single_new_signer(
    sk: &SecretKey,
    calls: &[BinaryCallV1],
) -> Result<([u8; 96], Vec<u8>)> {
    let pk = sk.sk_to_pk();
    let pk_bytes = pk.to_bytes();

    // Concatenate postcard-encoded calls.
    let mut call_bytes_vec = Vec::with_capacity(calls.len());
    let mut concatenated_calls = Vec::new();
    for call in calls {
        let bytes = postcard::to_allocvec(call)?;
        concatenated_calls.extend_from_slice(&bytes);
        call_bytes_vec.push(bytes);
    }

    // Build signatures in the same order the indexer verifies:
    // 1) PoP signatures for new_signers
    // 2) op signatures for each call in order
    let mut sigs: Vec<BlsSignature> = Vec::with_capacity(1 + calls.len());
    sigs.push(sk.sign(&pop_message(&pk_bytes), PROTOCOL_BLS_DST, &[]));
    for (i, bytes) in call_bytes_vec.iter().enumerate() {
        sigs.push(sk.sign(&op_message(i as u32, bytes), PROTOCOL_BLS_DST, &[]));
    }

    let sig_refs: Vec<&BlsSignature> = sigs.iter().collect();
    let aggregate = AggregateSignature::aggregate(&sig_refs, true)
        .map_err(|e| anyhow::anyhow!("aggregate signature failed: {e:?}"))?;
    let aggregate_sig_bytes = aggregate.to_signature().to_bytes();

    // Compress concatenated calls.
    let compressed_calls = zstd::stream::encode_all(Cursor::new(concatenated_calls), 15)?;

    // KBL1 payload:
    // magic || compressed_calls_len || compressed_calls || aggregate_sig || new_signers_len || new_signers_bytes
    let mut payload = Vec::new();
    payload.extend_from_slice(b"KBL1");
    payload.extend_from_slice(&(compressed_calls.len() as u32).to_le_bytes());
    payload.extend_from_slice(&compressed_calls);
    payload.extend_from_slice(&aggregate_sig_bytes);
    payload.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&pk_bytes);

    Ok((pk_bytes, payload))
}

fn build_signed_kbl1_payload_single_new_signer_wrong_op_index(
    sk: &SecretKey,
    calls: &[BinaryCallV1],
) -> Result<([u8; 96], Vec<u8>)> {
    let pk = sk.sk_to_pk();
    let pk_bytes = pk.to_bytes();

    // Concatenate postcard-encoded calls.
    let mut call_bytes_vec = Vec::with_capacity(calls.len());
    let mut concatenated_calls = Vec::new();
    for call in calls {
        let bytes = postcard::to_allocvec(call)?;
        concatenated_calls.extend_from_slice(&bytes);
        call_bytes_vec.push(bytes);
    }

    // Same as normal signing except we intentionally use the wrong op_index for each call.
    // This should cause aggregate verification to fail.
    let mut sigs: Vec<BlsSignature> = Vec::with_capacity(1 + calls.len());
    sigs.push(sk.sign(&pop_message(&pk_bytes), PROTOCOL_BLS_DST, &[]));
    let n = call_bytes_vec.len();
    for (i, bytes) in call_bytes_vec.iter().enumerate() {
        let wrong_op_index = ((i + 1) % n) as u32;
        sigs.push(sk.sign(&op_message(wrong_op_index, bytes), PROTOCOL_BLS_DST, &[]));
    }

    let sig_refs: Vec<&BlsSignature> = sigs.iter().collect();
    let aggregate = AggregateSignature::aggregate(&sig_refs, true)
        .map_err(|e| anyhow::anyhow!("aggregate signature failed: {e:?}"))?;
    let aggregate_sig_bytes = aggregate.to_signature().to_bytes();

    // Compress concatenated calls.
    let compressed_calls = zstd::stream::encode_all(Cursor::new(concatenated_calls), 15)?;

    // KBL1 payload:
    // magic || compressed_calls_len || compressed_calls || aggregate_sig || new_signers_len || new_signers_bytes
    let mut payload = Vec::new();
    payload.extend_from_slice(b"KBL1");
    payload.extend_from_slice(&(compressed_calls.len() as u32).to_le_bytes());
    payload.extend_from_slice(&compressed_calls);
    payload.extend_from_slice(&aggregate_sig_bytes);
    payload.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&pk_bytes);

    Ok((pk_bytes, payload))
}

#[tokio::test]
async fn test_bls_batch_registers_signer_and_nonce_and_cascades_on_rollback() -> Result<()> {
    let setup_block = Block {
        height: 0,
        hash: BlockHash::from_byte_array([0x00; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    let (mut runtime, _temp_dir) = Runtime::new_local_with_block(&setup_block).await?;

    let sk = SecretKey::key_gen(&[42u8; 32], &[])
        .map_err(|e| anyhow::anyhow!("SecretKey::key_gen failed: {e:?}"))?;

    let nonce = 1u64;
    let calls = vec![BinaryCallV1 {
        signer: SignerRef::BundleIndex(0),
        contract_id: 999, // intentionally nonexistent; execution failure should not rollback nonce/registry
        function_index: 0,
        args: vec![],
        nonce,
        gas_limit: 1000,
    }];
    let (pk_bytes, payload) = build_signed_kbl1_payload_single_new_signer(&sk, &calls)?;

    let txid = Txid::from_slice(&[0x11; 32])?;
    let op = Op::BlsBatch {
        metadata: OpMetadata {
            previous_output: OutPoint { txid, vout: 0 },
            input_index: 0,
            signer: Signer::XOnlyPubKey("publisher".to_string()),
        },
        payload,
    };

    let block = Block {
        height: 1,
        hash: BlockHash::from_byte_array([0x01; 32]),
        prev_hash: setup_block.hash,
        transactions: vec![Transaction {
            txid,
            index: 0,
            ops: vec![op],
            op_return_data: IndexMap::new(),
        }],
    };

    reactor::block_handler(&mut runtime, &block).await?;

    let conn = runtime.get_storage_conn();
    let row = select_signer_registry_by_bls_pubkey(&conn, &pk_bytes)
        .await?
        .expect("new signer should be registered");

    assert!(
        signer_nonce_exists(&conn, row.id, nonce).await?,
        "nonce should be recorded for registered signer"
    );

    // Roll back by deleting the block row; our signer_registry / signer_nonces tables are
    // declared with ON DELETE CASCADE on the blocks(height) FK.
    rollback_to_height(&conn, 0).await?;

    assert!(
        select_signer_registry_by_bls_pubkey(&conn, &pk_bytes)
            .await?
            .is_none(),
        "signer_registry entry should cascade-delete on rollback"
    );
    assert!(
        !signer_nonce_exists(&conn, row.id, nonce).await?,
        "nonce entry should cascade-delete on rollback"
    );

    Ok(())
}

#[tokio::test]
async fn test_bls_batch_rejects_duplicate_nonce_within_batch() -> Result<()> {
    let setup_block = Block {
        height: 0,
        hash: BlockHash::from_byte_array([0x00; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    let (mut runtime, _temp_dir) = Runtime::new_local_with_block(&setup_block).await?;

    let sk = SecretKey::key_gen(&[99u8; 32], &[])
        .map_err(|e| anyhow::anyhow!("SecretKey::key_gen failed: {e:?}"))?;

    let nonce = 7u64;
    let calls = vec![
        BinaryCallV1 {
            signer: SignerRef::BundleIndex(0),
            contract_id: 999,
            function_index: 0,
            args: vec![],
            nonce,
            gas_limit: 1000,
        },
        BinaryCallV1 {
            signer: SignerRef::BundleIndex(0),
            contract_id: 999,
            function_index: 0,
            args: vec![],
            nonce,
            gas_limit: 1000,
        },
    ];
    let (pk_bytes, payload) = build_signed_kbl1_payload_single_new_signer(&sk, &calls)?;

    let txid = Txid::from_slice(&[0x22; 32])?;
    let op = Op::BlsBatch {
        metadata: OpMetadata {
            previous_output: OutPoint { txid, vout: 0 },
            input_index: 0,
            signer: Signer::XOnlyPubKey("publisher".to_string()),
        },
        payload,
    };

    let block = Block {
        height: 1,
        hash: BlockHash::from_byte_array([0x02; 32]),
        prev_hash: setup_block.hash,
        transactions: vec![Transaction {
            txid,
            index: 0,
            ops: vec![op],
            op_return_data: IndexMap::new(),
        }],
    };

    reactor::block_handler(&mut runtime, &block).await?;

    let conn = runtime.get_storage_conn();
    assert!(
        select_signer_registry_by_bls_pubkey(&conn, &pk_bytes)
            .await?
            .is_none(),
        "duplicate nonce should reject the whole batch and rollback registration"
    );

    Ok(())
}

#[tokio::test]
async fn test_bls_batch_records_nonces_for_multiple_calls() -> Result<()> {
    let setup_block = Block {
        height: 0,
        hash: BlockHash::from_byte_array([0x00; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    let (mut runtime, _temp_dir) = Runtime::new_local_with_block(&setup_block).await?;

    let sk = SecretKey::key_gen(&[7u8; 32], &[])
        .map_err(|e| anyhow::anyhow!("SecretKey::key_gen failed: {e:?}"))?;

    let nonce0 = 100u64;
    let nonce1 = 101u64;
    let calls = vec![
        BinaryCallV1 {
            signer: SignerRef::BundleIndex(0),
            contract_id: 999, // intentionally nonexistent
            function_index: 0,
            args: vec![],
            nonce: nonce0,
            gas_limit: 1000,
        },
        BinaryCallV1 {
            signer: SignerRef::BundleIndex(0),
            contract_id: 999, // intentionally nonexistent
            function_index: 0,
            args: vec![],
            nonce: nonce1,
            gas_limit: 1000,
        },
    ];
    let (pk_bytes, payload) = build_signed_kbl1_payload_single_new_signer(&sk, &calls)?;

    let txid = Txid::from_slice(&[0x33; 32])?;
    let op = Op::BlsBatch {
        metadata: OpMetadata {
            previous_output: OutPoint { txid, vout: 0 },
            input_index: 0,
            signer: Signer::XOnlyPubKey("publisher".to_string()),
        },
        payload,
    };

    let block = Block {
        height: 1,
        hash: BlockHash::from_byte_array([0x03; 32]),
        prev_hash: setup_block.hash,
        transactions: vec![Transaction {
            txid,
            index: 0,
            ops: vec![op],
            op_return_data: IndexMap::new(),
        }],
    };

    reactor::block_handler(&mut runtime, &block).await?;

    let conn = runtime.get_storage_conn();
    let row = select_signer_registry_by_bls_pubkey(&conn, &pk_bytes)
        .await?
        .expect("new signer should be registered");

    assert!(signer_nonce_exists(&conn, row.id, nonce0).await?);
    assert!(signer_nonce_exists(&conn, row.id, nonce1).await?);

    Ok(())
}

#[tokio::test]
async fn test_bls_batch_rejects_wrong_op_index_signing() -> Result<()> {
    let setup_block = Block {
        height: 0,
        hash: BlockHash::from_byte_array([0x00; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    let (mut runtime, _temp_dir) = Runtime::new_local_with_block(&setup_block).await?;

    let sk = SecretKey::key_gen(&[8u8; 32], &[])
        .map_err(|e| anyhow::anyhow!("SecretKey::key_gen failed: {e:?}"))?;

    let calls = vec![
        BinaryCallV1 {
            signer: SignerRef::BundleIndex(0),
            contract_id: 999,
            function_index: 0,
            args: vec![],
            nonce: 200u64,
            gas_limit: 1000,
        },
        BinaryCallV1 {
            signer: SignerRef::BundleIndex(0),
            contract_id: 999,
            function_index: 0,
            args: vec![],
            nonce: 201u64,
            gas_limit: 1000,
        },
    ];
    let (pk_bytes, payload) =
        build_signed_kbl1_payload_single_new_signer_wrong_op_index(&sk, &calls)?;

    let txid = Txid::from_slice(&[0x44; 32])?;
    let op = Op::BlsBatch {
        metadata: OpMetadata {
            previous_output: OutPoint { txid, vout: 0 },
            input_index: 0,
            signer: Signer::XOnlyPubKey("publisher".to_string()),
        },
        payload,
    };

    let block = Block {
        height: 1,
        hash: BlockHash::from_byte_array([0x04; 32]),
        prev_hash: setup_block.hash,
        transactions: vec![Transaction {
            txid,
            index: 0,
            ops: vec![op],
            op_return_data: IndexMap::new(),
        }],
    };

    reactor::block_handler(&mut runtime, &block).await?;

    let conn = runtime.get_storage_conn();
    assert!(
        select_signer_registry_by_bls_pubkey(&conn, &pk_bytes)
            .await?
            .is_none(),
        "bad op_index signing should fail verification and rollback registration"
    );

    Ok(())
}

#[tokio::test]
async fn test_bls_batch_rejects_invalid_new_signer_pubkey() -> Result<()> {
    let setup_block = Block {
        height: 0,
        hash: BlockHash::from_byte_array([0x00; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    let (mut runtime, _temp_dir) = Runtime::new_local_with_block(&setup_block).await?;

    // PublicKey::default() is the point at infinity; validate() must reject it.
    let pk_bytes = BlsPublicKey::default().to_bytes();

    let calls = vec![BinaryCallV1 {
        signer: SignerRef::BundleIndex(0),
        contract_id: 999,
        function_index: 0,
        args: vec![],
        nonce: 1u64,
        gas_limit: 1000,
    }];
    let concatenated_calls = postcard::to_allocvec(&calls[0])?;
    let compressed_calls = zstd::stream::encode_all(Cursor::new(concatenated_calls), 15)?;

    let mut payload = Vec::new();
    payload.extend_from_slice(b"KBL1");
    payload.extend_from_slice(&(compressed_calls.len() as u32).to_le_bytes());
    payload.extend_from_slice(&compressed_calls);
    payload.extend_from_slice(&[0u8; 48]); // invalid aggregate signature; we should fail earlier
    payload.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&pk_bytes);

    let txid = Txid::from_slice(&[0x55; 32])?;
    let op = Op::BlsBatch {
        metadata: OpMetadata {
            previous_output: OutPoint { txid, vout: 0 },
            input_index: 0,
            signer: Signer::XOnlyPubKey("publisher".to_string()),
        },
        payload,
    };

    let block = Block {
        height: 1,
        hash: BlockHash::from_byte_array([0x05; 32]),
        prev_hash: setup_block.hash,
        transactions: vec![Transaction {
            txid,
            index: 0,
            ops: vec![op],
            op_return_data: IndexMap::new(),
        }],
    };

    reactor::block_handler(&mut runtime, &block).await?;

    let conn = runtime.get_storage_conn();
    assert!(
        select_signer_registry_by_bls_pubkey(&conn, &pk_bytes)
            .await?
            .is_none(),
        "invalid new_signer pubkey should reject the batch before registration"
    );

    Ok(())
}

#[tokio::test]
async fn test_mixed_legacy_and_bls_ops_in_same_block() -> Result<()> {
    let setup_block = Block {
        height: 0,
        hash: BlockHash::from_byte_array([0x00; 32]),
        prev_hash: BlockHash::from_byte_array([0x00; 32]),
        transactions: vec![],
    };
    let (mut runtime, _temp_dir) = Runtime::new_local_with_block(&setup_block).await?;

    let sk = SecretKey::key_gen(&[55u8; 32], &[])
        .map_err(|e| anyhow::anyhow!("SecretKey::key_gen failed: {e:?}"))?;
    let calls = vec![BinaryCallV1 {
        signer: SignerRef::BundleIndex(0),
        contract_id: 999,
        function_index: 0,
        args: vec![],
        nonce: 9u64,
        gas_limit: 1000,
    }];
    let (pk_bytes, payload) = build_signed_kbl1_payload_single_new_signer(&sk, &calls)?;

    let txid = Txid::from_slice(&[0x66; 32])?;
    let legacy_call = Op::Call {
        metadata: OpMetadata {
            previous_output: OutPoint { txid, vout: 0 },
            input_index: 0,
            signer: Signer::XOnlyPubKey("publisher".to_string()),
        },
        gas_limit: 1_000_000,
        contract: ContractAddress {
            name: "does-not-exist".to_string(),
            height: 1,
            tx_index: 0,
        },
        expr: "noop()".to_string(),
    };

    let bls_batch = Op::BlsBatch {
        metadata: OpMetadata {
            previous_output: OutPoint { txid, vout: 0 },
            input_index: 0,
            signer: Signer::XOnlyPubKey("publisher".to_string()),
        },
        payload,
    };

    let block = Block {
        height: 1,
        hash: BlockHash::from_byte_array([0x06; 32]),
        prev_hash: setup_block.hash,
        transactions: vec![Transaction {
            txid,
            index: 0,
            ops: vec![legacy_call, bls_batch],
            op_return_data: IndexMap::new(),
        }],
    };

    reactor::block_handler(&mut runtime, &block).await?;

    let conn = runtime.get_storage_conn();
    assert!(
        select_signer_registry_by_bls_pubkey(&conn, &pk_bytes)
            .await?
            .is_some(),
        "BLS batch should still be processed even if legacy op fails"
    );

    Ok(())
}
