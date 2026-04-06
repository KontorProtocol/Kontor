use anyhow::Result;

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
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::time::{Duration, sleep};

use crate::database::queries::insert_block;
use crate::database::types::FileMetadataRow;
use crate::database::{Reader, Writer, queries};
use crate::runtime::{ComponentCache, GenesisValidator, RawFileDescriptor, Runtime, Storage};
use kontor_crypto::{api::FieldElement, field_from_uniform_bytes};

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
        inputs: vec![],
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

/// Shared engine + pre-compiled native contract components.
/// First caller compiles all native contracts; subsequent callers get cached results.
async fn shared_test_engine() -> (wasmtime::Engine, Vec<(i64, wasmtime::component::Component)>) {
    static ONCE: tokio::sync::OnceCell<(
        wasmtime::Engine,
        Vec<(i64, wasmtime::component::Component)>,
    )> = tokio::sync::OnceCell::const_new();

    ONCE.get_or_init(|| async {
        let engine = Runtime::new_engine().expect("Failed to create engine");
        let cache = ComponentCache::new();

        let (_reader, writer, (_db_dir, _db_name)) = new_test_db().await.expect("test db");
        let conn = writer.connection();
        insert_block(
            &conn,
            BlockRow::builder()
                .height(0)
                .hash(new_mock_block_hash(0))
                .relevant(true)
                .build(),
        )
        .await
        .expect("insert block");

        let storage = Storage::builder().height(0).conn(conn).build();
        let linker = Runtime::new_linker(&engine).expect("linker");
        let mut runtime = Runtime::new_with(engine.clone(), linker, cache.clone(), storage)
            .await
            .expect("runtime");
        runtime
            .publish_native_contracts(&[])
            .await
            .expect("publish native");

        // Extract compiled components from cache (IDs 1-4 for native contracts)
        let mut components = Vec::new();
        for id in 1..=4i64 {
            if let Some(component) = cache.get(&id).await {
                components.push((id, component));
            }
        }

        (engine, components)
    })
    .await
    .clone()
}

pub async fn test_runtime() -> Result<(Runtime, TempDir, String)> {
    test_runtime_with_genesis(&[]).await
}

pub async fn test_runtime_with_genesis(
    genesis_validators: &[GenesisValidator],
) -> Result<(Runtime, TempDir, String)> {
    let (_reader, writer, (db_dir, db_name)) = new_test_db().await?;
    let conn = writer.connection();

    insert_block(
        &conn,
        BlockRow::builder()
            .height(0)
            .hash(new_mock_block_hash(0))
            .relevant(true)
            .build(),
    )
    .await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(new_mock_block_hash(1))
            .relevant(true)
            .build(),
    )
    .await?;

    let storage = Storage::builder().height(1).conn(conn).build();
    let (engine, prewarmed) = shared_test_engine().await;
    let cache = ComponentCache::new();
    for (id, component) in &prewarmed {
        cache.put(*id, component.clone()).await;
    }
    let linker = Runtime::new_linker(&engine)?;
    let mut runtime = Runtime::new_with(engine, linker, cache, storage).await?;
    runtime.publish_native_contracts(genesis_validators).await?;

    Ok((runtime, db_dir, db_name))
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

pub async fn await_block_at_height(conn: &Connection, height: i64) -> BlockRow {
    loop {
        match queries::select_block_at_height(conn, height).await {
            Ok(Some(row)) => return row,
            Ok(None) => {}
            Err(e) => panic!("error: {:?}", e),
        };
        sleep(Duration::from_millis(10)).await;
    }
}

#[derive(Debug, Clone)]
pub struct ValidSeed {
    pub bytes: [u8; 64],
    pub field: FieldElement,
}

pub fn valid_seed_field(n: u64) -> ValidSeed {
    let mut bytes = [0u8; 64];
    bytes[..8].copy_from_slice(&n.to_le_bytes());

    // Fill the rest deterministically from SHA256 chaining to avoid obvious structure.
    let h1 = Sha256::digest(&bytes[..8]);
    let h2 = Sha256::digest(h1);
    bytes[8..40].copy_from_slice(&h1);
    bytes[40..64].copy_from_slice(&h2[..24]);

    let field = field_from_uniform_bytes(&bytes);
    ValidSeed { bytes, field }
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
        .object_id(format!("obj_{}", file_id))
        .nonce(nonce.to_vec())
        .root(root)
        .padded_len(1024)
        .original_size(512)
        .filename(filename.to_string())
        .height(height)
        .build()
}

pub fn make_descriptor(
    file_id: String,
    root: Vec<u8>,
    padded_len: u64,
    original_size: u64,
    filename: String,
) -> RawFileDescriptor {
    let object_id = format!("object_{}", file_id);
    let mut nonce = [0u8; 32];
    for (i, b) in file_id.bytes().enumerate().take(32) {
        nonce[i] = b;
    }

    RawFileDescriptor {
        file_id,
        object_id,
        nonce: nonce.to_vec(),
        root,
        padded_len,
        original_size,
        filename,
    }
}

// Pre-computed lucky block hashes for challenge generation tests.
// Each hash guarantees a challenge when there's 1 eligible file.
// Stored as hex strings for readability; use `lucky_hash()` to decode.

/// Lucky hash for block height 1000 (roll = 7)
pub const LUCKY_HASH_1000: &str =
    "8db6b1269eab0af290543fc6cc3945018ba7332085b18a71170ee234e4f43676";

/// Lucky hash for block height 10000 (roll = 10)
pub const LUCKY_HASH_10000: &str =
    "dda7bbc8c286d5f8a390fc7a9918a83eefd7046ad878a8feef7297560929c75d";

/// Lucky hash for block height 50000 (roll = 1)
pub const LUCKY_HASH_50000: &str =
    "d998f2928dab53f43cda61ed3bd6f2ebdbae001df799175ab28601bf16187e52";

/// Lucky hash for block height 100000 (roll = 2)
pub const LUCKY_HASH_100000: &str =
    "10adb611e366cab60d827a935bb4ced6431e36bd7576d38eb568084ab39d6bb1";

/// Lucky hash for block height 500000 (roll = 8)
pub const LUCKY_HASH_500000: &str =
    "e68680749dc7fd55901397031d27304d63d4efd3cb67e78a7cdb8e206a17c35b";

/// Decode a hex-encoded lucky hash to a 32-byte array.
pub fn lucky_hash(hex: &str) -> [u8; 32] {
    hex::decode(hex)
        .expect("Invalid hex string")
        .try_into()
        .expect("Hash must be exactly 32 bytes")
}

/// Test harness for running the production reactor with a single-validator
/// Malachite engine. Feeds blocks and mempool events through channels
/// (no poller/bitcoind needed). Uses a real RuntimeExecutor with temp DB.
pub mod reactor_harness {
    use std::time::Duration;

    use anyhow::Result;
    use tempfile::TempDir;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    use indexer_types::Block;

    use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
    use crate::consensus::finality_types::{DecidedBatch, FinalityEvent, StateEvent};
    use crate::consensus::signing::PrivateKey;
    use crate::reactor;
    use crate::reactor::consensus::ObservationChannels;
    use crate::reactor::engine::EngineConfig;
    use crate::runtime::GenesisValidator;

    /// Handle to a running single-validator test reactor.
    pub struct TestReactor {
        pub block_tx: mpsc::Sender<BlockEvent>,
        pub mempool_tx: mpsc::Sender<MempoolEvent>,
        pub decided_rx: mpsc::Receiver<DecidedBatch>,
        pub finality_rx: mpsc::Receiver<FinalityEvent>,
        pub state_rx: mpsc::Receiver<StateEvent>,
        pub cancel: CancellationToken,
        handle: JoinHandle<()>,
        _db_dir: TempDir,
    }

    impl TestReactor {
        /// Start a single-validator reactor with a fresh temp DB.
        pub async fn start() -> Result<Self> {
            let seed: [u8; 32] = [42; 32];
            let private_key = PrivateKey::from(seed);
            Self::start_with_key(private_key).await
        }

        /// Start with a specific private key.
        pub async fn start_with_key(private_key: PrivateKey) -> Result<Self> {
            let (_reader, writer, (db_dir, _db_name)) = super::new_test_db().await?;

            let genesis_validators = vec![GenesisValidator {
                x_only_pubkey: format!("{:064x}", 1),
                stake: crate::runtime::Decimal::from("100"),
                ed25519_pubkey: private_key.public_key().as_bytes().to_vec(),
            }];

            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            drop(listener);
            let ports = [port];
            let engine_config = EngineConfig {
                private_key,
                listen_addr: format!("/ip4/127.0.0.1/tcp/{}", ports[0]),
                persistent_peers: vec![],
                data_dir: db_dir.path().to_path_buf(),
            };

            let (block_tx, block_rx) = mpsc::channel(256);
            let (mempool_tx, mempool_rx) = mpsc::channel(256);

            let (decided_tx, decided_rx) = mpsc::channel(1024);
            let (finality_tx, finality_rx) = mpsc::channel(1024);
            let (state_tx, state_rx) = mpsc::channel(1024);

            let cancel = CancellationToken::new();

            let observation = ObservationChannels {
                decided_tx,
                finality_tx,
                state_tx,
            };

            let handle = reactor::run(
                1,
                cancel.clone(),
                writer,
                block_rx,
                mempool_rx,
                None,
                None,
                None,
                Some(engine_config),
                None,
                None,
                genesis_validators,
                Some(observation),
                None,
            );

            // Wait a bit for the reactor + Malachite to start up
            tokio::time::sleep(Duration::from_secs(2)).await;

            Ok(Self {
                block_tx,
                mempool_tx,
                decided_rx,
                finality_rx,
                state_rx,
                cancel,
                handle,
                _db_dir: db_dir,
            })
        }

        /// Send a block to the reactor.
        pub async fn send_block(&self, block: Block) {
            let target_height = block.height;
            let _ = self
                .block_tx
                .send(BlockEvent::BlockInsert {
                    target_height,
                    block,
                })
                .await;
        }

        /// Send a mempool transaction.
        pub async fn send_mempool_tx(&self, tx: bitcoin::Transaction) {
            let _ = self.mempool_tx.send(MempoolEvent::Insert(tx)).await;
        }

        /// Wait for state events.
        pub async fn wait_for_state_events(
            &mut self,
            count: usize,
            timeout: Duration,
        ) -> Vec<StateEvent> {
            let mut events = Vec::new();
            let deadline = tokio::time::sleep(timeout);
            tokio::pin!(deadline);

            loop {
                if events.len() >= count {
                    break;
                }
                tokio::select! {
                    _ = &mut deadline => break,
                    Some(event) = self.state_rx.recv() => {
                        events.push(event);
                    }
                }
            }
            events
        }

        /// Wait for decided batches.
        pub async fn wait_for_decisions(
            &mut self,
            count: usize,
            timeout: Duration,
        ) -> Vec<DecidedBatch> {
            let mut batches = Vec::new();
            let deadline = tokio::time::sleep(timeout);
            tokio::pin!(deadline);

            loop {
                if batches.len() >= count {
                    break;
                }
                tokio::select! {
                    _ = &mut deadline => break,
                    Some(batch) = self.decided_rx.recv() => {
                        batches.push(batch);
                    }
                }
            }
            batches
        }

        /// Wait for finality events.
        pub async fn wait_for_finality_events(
            &mut self,
            count: usize,
            timeout: Duration,
        ) -> Vec<FinalityEvent> {
            let mut events = Vec::new();
            let deadline = tokio::time::sleep(timeout);
            tokio::pin!(deadline);

            loop {
                if events.len() >= count {
                    break;
                }
                tokio::select! {
                    _ = &mut deadline => break,
                    Some(event) = self.finality_rx.recv() => {
                        events.push(event);
                    }
                }
            }
            events
        }

        /// Shut down the reactor.
        pub async fn shutdown(self) {
            self.cancel.cancel();
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop(self.handle);
        }
    }
}

/// BLS test helpers shared between unit and regtest attack vector tests.
pub mod bls_test {
    use blst::min_sig::{AggregatePublicKey, PublicKey as BlsPublicKey};

    pub fn derive_test_key(seed_byte: u8) -> blst::min_sig::SecretKey {
        let seed = [seed_byte; 64];
        crate::bls::derive_bls_secret_key_eip2333(
            &seed,
            &crate::bls::bls_derivation_path(bitcoin::Network::Regtest),
        )
        .expect("failed to derive EIP-2333 secret key")
    }

    pub fn construct_rogue_g2_pubkey(
        beta_pk_compressed: &[u8; 96],
        victim_pk_compressed: &[u8; 96],
    ) -> [u8; 96] {
        let beta_pk =
            BlsPublicKey::key_validate(beta_pk_compressed).expect("beta pk must be valid G2");
        let mut neg_victim_bytes = *victim_pk_compressed;
        neg_victim_bytes[0] ^= 0x20;
        let neg_victim_pk = BlsPublicKey::key_validate(&neg_victim_bytes)
            .expect("negated victim pk must be valid G2");
        let agg = AggregatePublicKey::aggregate(&[&beta_pk, &neg_victim_pk], false)
            .expect("aggregation must succeed");
        agg.to_public_key().to_bytes()
    }
}
