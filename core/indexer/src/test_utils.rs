use anyhow::{Error, Result};

use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::key::{CompressedPublicKey, Secp256k1};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::opcodes::{OP_0, OP_FALSE};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::{All, Keypair};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootSpendInfo};
use bitcoin::{
    BlockHash, Psbt, ScriptBuf, TapLeafHash, TapSighashType, TxOut, Txid, Witness, XOnlyPublicKey,
};
use indexer_types::{Block, BlockRow, Transaction};
use indexmap::IndexMap;
use libsql::Connection;
use rand::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::time::{Duration, sleep};

use crate::bitcoin_follower::blockchain_info::BlockchainInfo;
use crate::bitcoin_follower::rpc;

use crate::database::types::FileMetadataRow;
use crate::database::{Reader, Writer, queries};

pub enum PublicKey<'a> {
    Segwit(&'a CompressedPublicKey),
    Taproot(&'a XOnlyPublicKey),
}

fn build_script_after_pubkey(
    base_witness_script: Builder,
    serialized_token_balance: Vec<u8>,
) -> Result<Builder> {
    Ok(base_witness_script
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(serialized_token_balance)?)
        .push_opcode(OP_ENDIF))
}

pub fn build_inscription_without_checksig(
    serialized_token_balance: Vec<u8>,
    key: PublicKey,
) -> Result<Builder> {
    let base_witness_script = match key {
        PublicKey::Segwit(compressed) => Builder::new().push_slice(compressed.to_bytes()),
        PublicKey::Taproot(x_only) => Builder::new().push_slice(x_only.serialize()),
    };

    build_script_after_pubkey(base_witness_script, serialized_token_balance)
}

pub fn build_inscription(serialized_token_balance: Vec<u8>, key: PublicKey) -> Result<ScriptBuf> {
    let base_witness_script = match key {
        PublicKey::Segwit(compressed) => Builder::new()
            .push_slice(compressed.to_bytes())
            .push_opcode(OP_CHECKSIG),
        PublicKey::Taproot(x_only) => Builder::new()
            .push_slice(x_only.serialize())
            .push_opcode(OP_CHECKSIG),
    };

    let tap_script = build_script_after_pubkey(base_witness_script, serialized_token_balance)?;
    Ok(tap_script.into_script())
}

pub fn sign_key_spend(
    secp: &Secp256k1<All>,
    key_spend_tx: &mut bitcoin::Transaction,
    prevouts: &[TxOut],
    keypair: &Keypair,
    input_index: usize,
    sighash_type: Option<TapSighashType>,
) -> Result<()> {
    let sighash_type = sighash_type.unwrap_or(TapSighashType::Default);

    let mut sighasher = SighashCache::new(key_spend_tx.clone());
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &Prevouts::All(prevouts), sighash_type)
        .expect("Failed to construct sighash");

    let tweaked_sender = keypair.tap_tweak(secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &tweaked_sender.to_keypair());

    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    key_spend_tx.input[input_index]
        .witness
        .push(signature.to_vec());
    Ok(())
}

pub fn sign_script_spend(
    secp: &Secp256k1<All>,
    taproot_spend_info: &TaprootSpendInfo,
    tap_script: &ScriptBuf,
    script_spend_tx: &mut bitcoin::Transaction,
    prevouts: &[TxOut],
    keypair: &Keypair,
    input_index: usize,
) -> Result<()> {
    sign_script_spend_with_sighash(
        secp,
        taproot_spend_info,
        tap_script,
        script_spend_tx,
        prevouts,
        keypair,
        input_index,
        TapSighashType::Default,
    )
}

pub fn sign_script_spend_with_sighash(
    secp: &Secp256k1<All>,
    taproot_spend_info: &TaprootSpendInfo,
    tap_script: &ScriptBuf,
    script_spend_tx: &mut bitcoin::Transaction,
    prevouts: &[TxOut],
    keypair: &Keypair,
    input_index: usize,
    sighash_type: TapSighashType,
) -> Result<()> {
    let control_block = taproot_spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .expect("Failed to create control block");

    let mut sighasher = SighashCache::new(script_spend_tx.clone());
    let sighash = sighasher
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            TapLeafHash::from_script(tap_script, LeafVersion::TapScript),
            sighash_type,
        )
        .expect("Failed to create sighash");

    let msg: Message = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, keypair);

    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    script_spend_tx.input[input_index].witness = witness;
    Ok(())
}

pub fn sign_multiple_key_spend(
    secp: &Secp256k1<All>,
    key_spend_tx: &mut bitcoin::Transaction,
    prevouts: &[TxOut],
    keypair: &Keypair,
) -> Result<()> {
    let sighash_type = TapSighashType::Default;
    let tweaked_sender = keypair.tap_tweak(secp, None);

    // Create a single sighasher instance
    let mut sighasher = SighashCache::new(key_spend_tx.clone());

    // Collect all signatures first
    let mut signatures = Vec::new();
    for input_index in 0..key_spend_tx.input.len() {
        let sighash = sighasher
            .taproot_key_spend_signature_hash(input_index, &Prevouts::All(prevouts), sighash_type)
            .expect("Failed to construct sighash");

        let msg = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_schnorr(&msg, &tweaked_sender.to_keypair());

        let signature = bitcoin::taproot::Signature {
            signature,
            sighash_type,
        };

        signatures.push(signature);
    }

    // Apply all signatures to the transaction
    for (input_index, signature) in signatures.into_iter().enumerate() {
        key_spend_tx.input[input_index]
            .witness
            .push(signature.to_vec());
    }

    Ok(())
}

pub fn sign_seller_side_psbt(
    secp: &Secp256k1<All>,
    seller_psbt: &mut Psbt,
    tap_script: &ScriptBuf,
    seller_internal_key: XOnlyPublicKey,
    control_block: ControlBlock,
    seller_keypair: &Keypair,
    prevouts: &[TxOut],
) {
    // Sign the PSBT with seller's key for script path spending
    let sighash = SighashCache::new(&seller_psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(prevouts),
            TapLeafHash::from_script(tap_script, LeafVersion::TapScript),
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("Failed to create sighash");

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, seller_keypair);
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::SinglePlusAnyoneCanPay,
    };

    // Not necessary for test, but this is where the signature would be stored in the marketplace until it was ready to be spent
    seller_psbt.inputs[0].tap_script_sigs.insert(
        (
            seller_internal_key,
            TapLeafHash::from_script(tap_script, LeafVersion::TapScript),
        ),
        signature,
    );

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);
}

pub fn sign_buyer_side_psbt(
    secp: &Secp256k1<All>,
    buyer_psbt: &mut Psbt,
    buyer_keypair: &Keypair,
    prevouts: &[TxOut],
) {
    // Sign the buyer's input (key path spending)
    let buyer_sighash = {
        // Create a new SighashCache for the transaction
        let mut sighasher = SighashCache::new(&buyer_psbt.unsigned_tx);

        // Calculate the sighash for key path spending
        sighasher
            .taproot_key_spend_signature_hash(
                1, // Buyer's input index (back to 1)
                &Prevouts::All(prevouts),
                TapSighashType::Default,
            )
            .expect("Failed to create sighash")
    };

    // Sign with the buyer's tweaked key
    let msg = Message::from_digest(buyer_sighash.to_byte_array());

    // Create the tweaked keypair
    let buyer_tweaked = buyer_keypair.tap_tweak(secp, None);
    // Sign with the tweaked keypair since we're doing key path spending
    let buyer_signature = secp.sign_schnorr(&msg, &buyer_tweaked.to_keypair());

    let buyer_signature = bitcoin::taproot::Signature {
        signature: buyer_signature,
        sighash_type: TapSighashType::Default,
    };

    // Add the signature to the PSBT
    buyer_psbt.inputs[1].tap_key_sig = Some(buyer_signature);

    // Construct the witness stack for key path spending
    let mut buyer_witness = Witness::new();
    buyer_witness.push(buyer_signature.to_vec());
    buyer_psbt.inputs[1].final_script_witness = Some(buyer_witness);
}

pub fn new_mock_transaction(txid_num: u32) -> Transaction {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&txid_num.to_le_bytes()); // Use the 4 bytes of txid_num
    Transaction {
        txid: Txid::from_slice(&bytes).unwrap(),
        index: 0,
        ops: vec![],
        op_return_data: IndexMap::new(),
    }
}

pub async fn new_test_db() -> Result<(Reader, Writer, (TempDir, String))> {
    let temp_dir = TempDir::new()?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let db_name = format!("test_db_{}.db", timestamp);
    let data_dir = temp_dir.path();
    let writer = Writer::new(data_dir, &db_name).await?;
    let reader = Reader::new(data_dir, &db_name).await?; // Assuming Reader::new exists
    Ok((reader, writer, (temp_dir, db_name)))
}

pub fn new_mock_block_hash(i: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    let i_bytes = i.to_le_bytes();
    for chunk in bytes.chunks_mut(4) {
        chunk.copy_from_slice(&i_bytes[..chunk.len()]);
    }
    BlockHash::from_slice(&bytes).unwrap()
}

pub fn gen_numbered_block(height: u64, prev_hash: &BlockHash) -> Block {
    let hash = BlockHash::from_byte_array([height as u8; 32]);

    Block {
        height,
        hash,
        prev_hash: *prev_hash,
        transactions: vec![new_mock_transaction(height as u32)],
    }
}

pub fn gen_numbered_blocks(start: u64, end: u64, prev_hash: BlockHash) -> Vec<Block> {
    let mut blocks = vec![];
    let mut prev = prev_hash;

    for _i in start..end {
        let block = gen_numbered_block(_i + 1, &prev);
        prev = block.hash;
        blocks.push(block.clone());
    }

    blocks
}

pub fn new_numbered_blockchain(n: u64) -> Vec<Block> {
    gen_numbered_blocks(0, n, BlockHash::from_byte_array([0x00; 32]))
}

pub fn gen_random_block(height: u64, prev_hash: Option<BlockHash>) -> Block {
    let mut hash = [0u8; 32];
    rand::rng().fill_bytes(&mut hash);

    let prev = match prev_hash {
        Some(h) => h,
        None => BlockHash::from_byte_array([0x00; 32]),
    };

    Block {
        height,
        hash: BlockHash::from_byte_array(hash),
        prev_hash: prev,
        transactions: vec![],
    }
}

pub fn gen_random_blocks(start: u64, end: u64, prev_hash: Option<BlockHash>) -> Vec<Block> {
    let mut blocks = vec![];
    let mut prev = prev_hash;

    for _i in start..end {
        let block = gen_random_block(_i + 1, prev);
        prev = Some(block.hash);
        blocks.push(block.clone());
    }

    blocks
}

pub fn new_random_blockchain(n: u64) -> Vec<Block> {
    gen_random_blocks(0, n, None)
}

#[derive(Clone, Debug)]
struct State {
    start_height: u64,
    running: bool,
    blocks: Vec<Block>,
    mempool: Vec<Transaction>,
}

#[derive(Clone, Debug)]
pub struct MockBlockchain {
    state: Arc<Mutex<State>>,
}

impl MockBlockchain {
    pub fn new(blocks: Vec<Block>) -> Self {
        Self {
            state: Mutex::new(State {
                start_height: 0,
                running: false,
                blocks,
                mempool: vec![],
            })
            .into(),
        }
    }

    pub fn append_blocks(&mut self, more_blocks: Vec<Block>) {
        let mut state = self.state.lock().unwrap();
        state.blocks.extend(more_blocks.iter().cloned());
    }

    pub fn replace_blocks(&mut self, blocks: Vec<Block>) {
        let mut state = self.state.lock().unwrap();
        state.blocks = blocks;
    }

    pub fn set_mempool(&mut self, mempool: Vec<Transaction>) {
        let mut state = self.state.lock().unwrap();
        state.mempool = mempool;
    }

    pub fn get_mempool(&mut self) -> Result<Vec<Transaction>> {
        let state = self.state.lock().unwrap();
        Ok(state.mempool.clone())
    }

    pub fn blocks(&self) -> Vec<Block> {
        let state = self.state.lock().unwrap();
        state.blocks.clone()
    }

    pub async fn get_blockchain_height(&self) -> Result<u64, Error> {
        let state = self.state.lock().unwrap();
        Ok(state.blocks.len() as u64)
    }

    pub fn start_height(&self) -> u64 {
        self.state.lock().unwrap().start_height
    }

    pub fn running(&self) -> bool {
        self.state.lock().unwrap().running
    }

    pub async fn await_running(&self) {
        loop {
            if self.state.lock().unwrap().running {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn await_stopped(&self) {
        loop {
            if !self.state.lock().unwrap().running {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn await_start_height(&self, height: u64) {
        loop {
            if self.state.lock().unwrap().start_height == height {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
}

impl rpc::BlockFetcher for MockBlockchain {
    fn running(&self) -> bool {
        self.running()
    }

    fn start(&mut self, start_height: u64) {
        let mut state = self.state.lock().unwrap();

        state.running = true;
        state.start_height = start_height;
    }

    async fn stop(&mut self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.running = false;
        Ok(())
    }
}

impl BlockchainInfo for MockBlockchain {
    async fn get_blockchain_height(&self) -> Result<u64, Error> {
        self.get_blockchain_height().await
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        let state = self.state.lock().unwrap();
        Ok(state.blocks[height as usize - 1].hash)
    }
}

impl rpc::MempoolFetcher for MockBlockchain {
    async fn get_mempool(&mut self) -> Result<Vec<Transaction>> {
        self.get_mempool()
    }
}

pub async fn await_block_at_height(conn: &Connection, height: i64) -> BlockRow {
    loop {
        match queries::select_processed_block_at_height(conn, height).await {
            Ok(Some(row)) => return row,
            Ok(None) => {}
            Err(e) => panic!("error: {:?}", e),
        };
        sleep(Duration::from_millis(10)).await;
    }
}

/// Helper to create a fake FileMetadataRow for testing.
pub fn create_fake_file_metadata(file_id: &str, filename: &str, height: i64) -> FileMetadataRow {
    // Create a simple valid root (32 bytes, small enough to be a valid field element)
    let mut root = [0u8; 32];
    root[0] = 1; // Non-zero but small value

    // Create a simple nonce
    let mut nonce = [0u8; 32];
    nonce[0] = 2;

    FileMetadataRow::builder()
        .file_id(file_id.to_string())
        .object_id(format!("object_{}", file_id))
        .nonce(nonce)
        .root(root)
        .padded_len(1024)
        .original_size(512)
        .filename(filename.to_string())
        .height(height)
        .build()
}
