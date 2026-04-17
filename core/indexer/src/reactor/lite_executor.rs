use std::sync::{Arc, Mutex};

use anyhow::Result;
use bitcoin::Txid;

use crate::database::queries::{
    contract_has_state, get_transaction_by_txid, insert_block, insert_contract, insert_transaction,
};
use crate::database::types::ContractRow;
use crate::reactor::executor::Executor;
use crate::reactor::mock_bitcoin::MockBitcoin;
use crate::runtime::wit::Signer;
use crate::runtime::{ComponentCache, ContractAddress, Runtime, Storage, TransactionContext};
use crate::test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db};
use indexer_types::{BlockRow, TransactionRow};
use testlib::ContractReader;

pub async fn shared_engine_and_cache() -> (wasmtime::Engine, ComponentCache) {
    static ONCE: tokio::sync::OnceCell<(wasmtime::Engine, ComponentCache)> =
        tokio::sync::OnceCell::const_new();
    ONCE.get_or_init(|| async {
        let engine = Runtime::new_engine().expect("Failed to create shared engine");
        let cache = ComponentCache::new();
        let mock_btc = Arc::new(Mutex::new(MockBitcoin::new(0)));
        let (dummy_tx, _dummy_rx) = tokio::sync::mpsc::channel(1);
        let (_executor, runtime) = LiteExecutor::new(
            mock_btc,
            "prewarm".to_string(),
            &[],
            engine.clone(),
            cache.clone(),
            dummy_tx,
        )
        .await
        .expect("pre-warm setup failed");
        drop(runtime);
        (engine, cache)
    })
    .await
    .clone()
}

pub struct LiteExecutor {
    _db_dir: tempfile::TempDir,
    counter_address: ContractAddress,
    signer: Signer,
    mock_bitcoin: Arc<Mutex<MockBitcoin>>,
    block_tx: tokio::sync::mpsc::Sender<crate::bitcoin_follower::event::BlockEvent>,
}

impl LiteExecutor {
    pub fn data_dir(&self) -> std::path::PathBuf {
        self._db_dir.path().to_path_buf()
    }

    pub async fn new(
        mock_bitcoin: Arc<Mutex<MockBitcoin>>,
        shared_pubkey: String,
        genesis_validators: &[crate::runtime::GenesisValidator],
        engine: wasmtime::Engine,
        component_cache: ComponentCache,
        block_tx: tokio::sync::mpsc::Sender<crate::bitcoin_follower::event::BlockEvent>,
    ) -> Result<(Self, Runtime)> {
        let (_reader, writer, (db_dir, _db_name)) = new_test_db().await?;
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

        let storage = Storage::builder().height(0).conn(conn).build();
        let linker = Runtime::new_linker(&engine)?;
        let mut runtime = Runtime::new_with(engine, linker, component_cache, storage).await?;
        runtime.publish_native_contracts(genesis_validators).await?;

        let identity = runtime.get_or_create_identity(&shared_pubkey).await?;
        let signer = Signer::Id(identity);
        runtime.issuance(&signer).await?;

        let contract_reader = ContractReader::new("../../test-contracts").await?;
        let counter_bytes = contract_reader
            .read("counter")
            .await?
            .expect("counter contract WASM not found");

        let mock_tx = new_mock_transaction(1);
        let conn = runtime.get_storage_conn();
        if get_transaction_by_txid(&conn, &mock_tx.txid.to_string())
            .await?
            .is_none()
        {
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(0)
                    .tx_index(0)
                    .txid(mock_tx.txid.to_string())
                    .build(),
            )
            .await?;
        }

        let counter_address = ContractAddress {
            name: "counter".to_string(),
            height: 0,
            tx_index: 0,
        };

        let contract_id = insert_contract(
            &conn,
            ContractRow::builder()
                .height(0)
                .tx_index(0)
                .name("counter".to_string())
                .bytes(counter_bytes)
                .build(),
        )
        .await?;

        if !contract_has_state(&conn, contract_id).await? {
            runtime
                .set_context(
                    0,
                    Some(
                        TransactionContext::builder()
                            .tx_index(0)
                            .txid(mock_tx.txid)
                            .build(),
                    ),
                    None,
                    None,
                )
                .await;
            runtime
                .execute(Some(&signer), &counter_address, "init()")
                .await?;
        }

        Ok((
            Self {
                _db_dir: db_dir,
                counter_address,
                signer,
                mock_bitcoin,
                block_tx,
            },
            runtime,
        ))
    }
}

impl Executor for LiteExecutor {
    async fn validate_transaction(
        &self,
        _raw: &bitcoin::Transaction,
        _parsed: &indexer_types::Transaction,
    ) -> bool {
        true
    }

    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        self.mock_bitcoin.lock().unwrap().get_raw_transaction(txid)
    }

    async fn execute_transaction(
        &self,
        runtime: &mut Runtime,
        height: i64,
        tx_id: i64,
        tx: &indexer_types::Transaction,
    ) -> anyhow::Result<()> {
        runtime
            .set_context(
                height,
                Some(
                    TransactionContext::builder()
                        .tx_id(tx_id)
                        .tx_index(tx.index)
                        .txid(tx.txid)
                        .build(),
                ),
                None,
                None,
            )
            .await;

        match runtime
            .execute(Some(&self.signer), &self.counter_address, "increment()")
            .await
        {
            Ok(_) => Ok(()),
            Err(crate::runtime::ExecutionError::Deterministic(e)) => {
                tracing::error!("counter increment error: {e}");
                Ok(())
            }
            Err(crate::runtime::ExecutionError::NonDeterministic(e)) => Err(e),
        }
    }

    async fn replay_blocks_from(&mut self, height: u64) -> anyhow::Result<()> {
        let events = self.mock_bitcoin.lock().unwrap().get_all_block_events();
        for event in events {
            if let crate::bitcoin_follower::event::BlockEvent::BlockInsert { block, .. } = &event
                && block.height >= height
            {
                let _ = self.block_tx.send(event).await;
            }
        }
        Ok(())
    }

    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        Some(indexer_types::Transaction {
            txid: tx.compute_txid(),
            index: 0,
            inputs: vec![],
            op_return_data: Default::default(),
        })
    }
}
