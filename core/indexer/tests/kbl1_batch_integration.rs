use anyhow::Result;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{All, Keypair, Message, Secp256k1};
use bitcoin::{OutPoint, Txid};
use indexer::batch::{BatchOpV1, SignerRefV1};
use indexer::database::queries::{
    insert_processed_block, select_signer_nonce, select_signer_registry_by_xonly,
};
use indexer::reactor::block_handler;
use indexer::runtime::{ComponentCache, Runtime, Storage};
use indexer::test_utils::new_test_db;
use indexer_types::{Block, BlockRow, Inst, Op, OpMetadata, Signer, Transaction};
use indexmap::IndexMap;

use blst::min_sig::SecretKey as BlsSecretKey;

const SCHNORR_BINDING_PREFIX: &[u8] = b"KONTOR_REG_XONLY_TO_BLS_V1";
const BLS_BINDING_PREFIX: &[u8] = b"KONTOR_REG_BLS_TO_XONLY_V1";

fn schnorr_binding_message(bls_pubkey: &[u8; 96]) -> Message {
    let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + bls_pubkey.len());
    preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
    preimage.extend_from_slice(bls_pubkey);
    let digest = sha256::Hash::hash(&preimage).to_byte_array();
    Message::from_digest_slice(&digest).expect("sha256 digest is 32 bytes")
}

fn bls_binding_message(xonly_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + xonly_pubkey.len());
    msg.extend_from_slice(BLS_BINDING_PREFIX);
    msg.extend_from_slice(xonly_pubkey);
    msg
}

fn build_kbl1_payload(decompressed_ops: &[u8], aggregate_signature: &[u8; 48]) -> Result<Vec<u8>> {
    let compressed = zstd::stream::encode_all(std::io::Cursor::new(decompressed_ops), 1)?;
    let compressed_len: u32 = compressed
        .len()
        .try_into()
        .expect("compressed length fits u32 for tests");
    let mut payload = Vec::with_capacity(4 + 4 + compressed.len() + 48);
    payload.extend_from_slice(indexer::batch::KBL1_MAGIC);
    payload.extend_from_slice(&compressed_len.to_le_bytes());
    payload.extend_from_slice(&compressed);
    payload.extend_from_slice(aggregate_signature);
    Ok(payload)
}

async fn new_runtime_with_native_contracts() -> Result<(Runtime, libsql::Connection)> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();

    // Ensure native block exists so contract inserts at height 0 satisfy FK constraints.
    insert_processed_block(
        &conn,
        BlockRow::builder()
            .height(0)
            .hash(indexer::test_utils::new_mock_block_hash(0))
            .relevant(true)
            .build(),
    )
    .await?;

    let storage = Storage::builder().height(0).conn(conn.clone()).build();
    let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
    runtime.publish_native_contracts().await?;
    Ok((runtime, conn))
}

#[tokio::test]
async fn kbl1_inline_register_then_issuance_reserves_nonce() -> Result<()> {
    let (mut runtime, conn) = new_runtime_with_native_contracts().await?;

    let secp: Secp256k1<All> = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &[9u8; 32])?;
    let (xonly, _) = keypair.public_key().x_only_public_key();
    let xonly_bytes = xonly.serialize();

    let bls_sk = BlsSecretKey::key_gen(&[7u8; 32], &[]).expect("bls sk");
    let bls_pk = bls_sk.sk_to_pk().to_bytes();

    let schnorr_sig = secp
        .sign_schnorr(&schnorr_binding_message(&bls_pk), &keypair)
        .serialize();
    let bls_sig = bls_sk
        .sign(
            &bls_binding_message(&xonly_bytes),
            indexer::bls::KONTOR_BLS_DST,
            &[],
        )
        .to_bytes();

    let register = BatchOpV1::RegisterSigner {
        xonly_pubkey: xonly_bytes,
        bls_pubkey: bls_pk.to_vec(),
        schnorr_sig: schnorr_sig.to_vec(),
        bls_sig: bls_sig.to_vec(),
    };
    let call = BatchOpV1::Op {
        signer: SignerRefV1::XOnly(xonly_bytes),
        nonce: 1,
        inst: Inst::Issuance,
    };

    let register_bytes = postcard::to_allocvec(&register)?;
    let call_bytes = postcard::to_allocvec(&call)?;
    let mut decompressed = Vec::new();
    decompressed.extend_from_slice(&register_bytes);
    decompressed.extend_from_slice(&call_bytes);

    let msg = indexer::batch::kbl1_message_for_op_bytes(&call_bytes);
    let sig = bls_sk
        .sign(&msg, indexer::bls::KONTOR_BLS_DST, &[])
        .to_bytes();

    let payload = build_kbl1_payload(&decompressed, &sig)?;

    let prevout = OutPoint {
        txid: Txid::from_slice(&[1u8; 32]).unwrap(),
        vout: 0,
    };
    let txid = Txid::from_slice(&[2u8; 32]).unwrap();
    let tx = Transaction {
        txid,
        index: 0,
        ops: vec![Op::Batch {
            metadata: OpMetadata {
                previous_output: prevout,
                input_index: 0,
                signer: Signer::XOnlyPubKey(xonly.to_string()), // publisher (not used for auth)
            },
            payload,
        }],
        op_return_data: IndexMap::new(),
    };

    let block = Block {
        height: 1,
        hash: indexer::test_utils::new_mock_block_hash(1),
        prev_hash: indexer::test_utils::new_mock_block_hash(0),
        transactions: vec![tx],
    };

    block_handler(&mut runtime, &block).await?;

    let row = select_signer_registry_by_xonly(&conn, &xonly_bytes)
        .await?
        .expect("signer should be registered");
    let signer_id: u32 = row.id.try_into().expect("signer_id fits u32");

    let nonce = select_signer_nonce(&conn, signer_id, 1)
        .await?
        .expect("nonce should be reserved");
    assert_eq!(nonce.height, 1);
    assert_eq!(nonce.op_index, 0);
    Ok(())
}

#[tokio::test]
async fn kbl1_invalid_signature_does_not_reserve_nonce() -> Result<()> {
    let (mut runtime, conn) = new_runtime_with_native_contracts().await?;

    let secp: Secp256k1<All> = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &[10u8; 32])?;
    let (xonly, _) = keypair.public_key().x_only_public_key();
    let xonly_bytes = xonly.serialize();

    let bls_sk = BlsSecretKey::key_gen(&[8u8; 32], &[]).expect("bls sk");
    let bls_pk = bls_sk.sk_to_pk().to_bytes();

    let schnorr_sig = secp
        .sign_schnorr(&schnorr_binding_message(&bls_pk), &keypair)
        .serialize();
    let bls_sig = bls_sk
        .sign(
            &bls_binding_message(&xonly_bytes),
            indexer::bls::KONTOR_BLS_DST,
            &[],
        )
        .to_bytes();

    let register = BatchOpV1::RegisterSigner {
        xonly_pubkey: xonly_bytes,
        bls_pubkey: bls_pk.to_vec(),
        schnorr_sig: schnorr_sig.to_vec(),
        bls_sig: bls_sig.to_vec(),
    };
    let call = BatchOpV1::Op {
        signer: SignerRefV1::XOnly(xonly_bytes),
        nonce: 7,
        inst: Inst::Issuance,
    };

    let register_bytes = postcard::to_allocvec(&register)?;
    let call_bytes = postcard::to_allocvec(&call)?;
    let mut decompressed = Vec::new();
    decompressed.extend_from_slice(&register_bytes);
    decompressed.extend_from_slice(&call_bytes);

    let bad_sig = [0u8; 48];
    let payload = build_kbl1_payload(&decompressed, &bad_sig)?;

    let prevout = OutPoint {
        txid: Txid::from_slice(&[3u8; 32]).unwrap(),
        vout: 0,
    };
    let txid = Txid::from_slice(&[4u8; 32]).unwrap();
    let tx = Transaction {
        txid,
        index: 0,
        ops: vec![Op::Batch {
            metadata: OpMetadata {
                previous_output: prevout,
                input_index: 0,
                signer: Signer::XOnlyPubKey(xonly.to_string()),
            },
            payload,
        }],
        op_return_data: IndexMap::new(),
    };

    let block = Block {
        height: 1,
        hash: indexer::test_utils::new_mock_block_hash(1),
        prev_hash: indexer::test_utils::new_mock_block_hash(0),
        transactions: vec![tx],
    };

    block_handler(&mut runtime, &block).await?;

    let row = select_signer_registry_by_xonly(&conn, &xonly_bytes)
        .await?
        .expect("signer should be registered");
    let signer_id: u32 = row.id.try_into().expect("signer_id fits u32");

    assert!(select_signer_nonce(&conn, signer_id, 7).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn mixed_legacy_and_kbl1_ops_in_one_block() -> Result<()> {
    let (mut runtime, conn) = new_runtime_with_native_contracts().await?;

    let secp: Secp256k1<All> = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &[11u8; 32])?;
    let (xonly, _) = keypair.public_key().x_only_public_key();
    let xonly_bytes = xonly.serialize();

    let bls_sk = BlsSecretKey::key_gen(&[9u8; 32], &[]).expect("bls sk");
    let bls_pk = bls_sk.sk_to_pk().to_bytes();

    let schnorr_sig = secp
        .sign_schnorr(&schnorr_binding_message(&bls_pk), &keypair)
        .serialize();
    let bls_sig = bls_sk
        .sign(
            &bls_binding_message(&xonly_bytes),
            indexer::bls::KONTOR_BLS_DST,
            &[],
        )
        .to_bytes();

    let register = BatchOpV1::RegisterSigner {
        xonly_pubkey: xonly_bytes,
        bls_pubkey: bls_pk.to_vec(),
        schnorr_sig: schnorr_sig.to_vec(),
        bls_sig: bls_sig.to_vec(),
    };
    let call = BatchOpV1::Op {
        signer: SignerRefV1::XOnly(xonly_bytes),
        nonce: 42,
        inst: Inst::Issuance,
    };

    let register_bytes = postcard::to_allocvec(&register)?;
    let call_bytes = postcard::to_allocvec(&call)?;
    let mut decompressed = Vec::new();
    decompressed.extend_from_slice(&register_bytes);
    decompressed.extend_from_slice(&call_bytes);

    let msg = indexer::batch::kbl1_message_for_op_bytes(&call_bytes);
    let sig = bls_sk
        .sign(&msg, indexer::bls::KONTOR_BLS_DST, &[])
        .to_bytes();

    let payload = build_kbl1_payload(&decompressed, &sig)?;

    let prevout0 = OutPoint {
        txid: Txid::from_slice(&[5u8; 32]).unwrap(),
        vout: 0,
    };
    let prevout1 = OutPoint {
        txid: Txid::from_slice(&[6u8; 32]).unwrap(),
        vout: 0,
    };
    let txid = Txid::from_slice(&[7u8; 32]).unwrap();

    let tx = Transaction {
        txid,
        index: 0,
        ops: vec![
            Op::Issuance {
                metadata: OpMetadata {
                    previous_output: prevout0,
                    input_index: 0,
                    signer: Signer::XOnlyPubKey(xonly.to_string()),
                },
            },
            Op::Batch {
                metadata: OpMetadata {
                    previous_output: prevout1,
                    input_index: 1,
                    signer: Signer::XOnlyPubKey(xonly.to_string()),
                },
                payload,
            },
        ],
        op_return_data: IndexMap::new(),
    };

    let block = Block {
        height: 1,
        hash: indexer::test_utils::new_mock_block_hash(1),
        prev_hash: indexer::test_utils::new_mock_block_hash(0),
        transactions: vec![tx],
    };

    block_handler(&mut runtime, &block).await?;

    let row = select_signer_registry_by_xonly(&conn, &xonly_bytes)
        .await?
        .expect("signer should be registered");
    let signer_id: u32 = row.id.try_into().expect("signer_id fits u32");
    assert!(select_signer_nonce(&conn, signer_id, 42).await?.is_some());
    Ok(())
}

