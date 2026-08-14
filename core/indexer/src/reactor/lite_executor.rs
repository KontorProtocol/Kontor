use std::path::{Path, PathBuf};
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
use crate::test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db_dir, open_test_db};
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
        let (dir, db_name) = new_test_db_dir().expect("prewarm dir");
        let (_executor, runtime) = LiteExecutor::new(
            dir.path(),
            &db_name,
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
    /// The directory is owned by the CLUSTER, not by us: a node that stops must
    /// leave its database behind so it can be restarted onto it.
    data_dir: PathBuf,
    counter_address: ContractAddress,
    signer: Signer,
    mock_bitcoin: Arc<Mutex<MockBitcoin>>,
    block_tx: tokio::sync::mpsc::Sender<crate::bitcoin_follower::event::BlockEvent>,
    /// Artificial latency for `validate_txs`, so tests can hold a validation
    /// in flight and assert the event loop keeps serving its other arms.
    validation_delay: Option<std::time::Duration>,
}

impl LiteExecutor {
    pub fn data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    /// Bring a node back up on a database it already has — no genesis seeding.
    /// The counterpart to `new`, and what makes a restart mean anything: the node
    /// must recover from durable state rather than starting fresh.
    pub async fn reopen(
        data_dir: &Path,
        db_name: &str,
        mock_bitcoin: Arc<Mutex<MockBitcoin>>,
        shared_pubkey: String,
        engine: wasmtime::Engine,
        component_cache: ComponentCache,
        block_tx: tokio::sync::mpsc::Sender<crate::bitcoin_follower::event::BlockEvent>,
    ) -> Result<(Self, Runtime)> {
        let (_reader, writer) = open_test_db(data_dir, db_name).await?;
        let storage = Storage::builder()
            .height(0)
            .conn(writer.connection())
            .build();
        let linkers = Runtime::new_linkers(&engine)?;
        let runtime = Runtime::new_with(engine, linkers, component_cache, storage).await?;

        // Already persisted by the first boot — this resolves the existing row.
        let identity = runtime.get_or_create_identity(&shared_pubkey).await?;

        Ok((
            Self {
                data_dir: data_dir.to_path_buf(),
                counter_address: ContractAddress {
                    name: "counter".to_string(),
                    height: 0,
                    tx_index: 0,
                },
                signer: Signer::Id(identity),
                mock_bitcoin,
                block_tx,
                validation_delay: None,
            },
            runtime,
        ))
    }

    pub async fn new(
        data_dir: &Path,
        db_name: &str,
        mock_bitcoin: Arc<Mutex<MockBitcoin>>,
        shared_pubkey: String,
        genesis_validators: &[crate::runtime::GenesisValidator],
        engine: wasmtime::Engine,
        component_cache: ComponentCache,
        block_tx: tokio::sync::mpsc::Sender<crate::bitcoin_follower::event::BlockEvent>,
    ) -> Result<(Self, Runtime)> {
        let (_reader, writer) = open_test_db(data_dir, db_name).await?;
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
        let linkers = Runtime::new_linkers(&engine)?;
        let mut runtime = Runtime::new_with(engine, linkers, component_cache, storage).await?;
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
            let payment = indexer_types::Payment {
                signer_id: signer.signer_id().expect("test signer must have id"),
                gas_limit: runtime.gas_limit_for_non_procs,
            };
            runtime
                .execute(Some(&signer), Some(payment), &counter_address, "init()")
                .await?;
        }

        Ok((
            Self {
                data_dir: data_dir.to_path_buf(),
                counter_address,
                signer,
                mock_bitcoin,
                block_tx,
                validation_delay: None,
            },
            runtime,
        ))
    }
}

impl LiteExecutor {
    /// Hold every `validate_txs` open for `delay` (non-empty candidate sets
    /// only, like production: zero txs means zero RPCs). Lets a test pin the
    /// event loop live while consensus I/O is in flight.
    pub fn set_validation_delay(&mut self, delay: std::time::Duration) {
        self.validation_delay = Some(delay);
    }
}

impl Executor for LiteExecutor {
    fn validate_txs(
        &self,
        txs: Vec<bitcoin::Transaction>,
        _threshold_sat_per_vb: u64,
    ) -> futures_util::future::BoxFuture<'static, anyhow::Result<Vec<super::executor::TxPolicy>>>
    {
        let delay = self.validation_delay;
        Box::pin(async move {
            if let Some(delay) = delay
                && !txs.is_empty()
            {
                tokio::time::sleep(delay).await;
            }
            Ok(txs
                .iter()
                .map(|_| super::executor::TxPolicy::Accepted)
                .collect())
        })
    }

    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        self.mock_bitcoin.lock().unwrap().get_raw_transaction(txid)
    }

    async fn execute_transaction(
        &self,
        runtime: &mut Runtime,
        height: u64,
        tx_id: u64,
        tx: &indexer_types::Transaction,
    ) -> anyhow::Result<Vec<Vec<Option<anyhow::Error>>>> {
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

        let payment = indexer_types::Payment {
            signer_id: self.signer.signer_id().unwrap_or(0),
            gas_limit: runtime.gas_limit_for_non_procs,
        };
        match runtime
            .execute(
                Some(&self.signer),
                Some(payment),
                &self.counter_address,
                "increment()",
            )
            .await
        {
            Ok(_) => Ok(vec![vec![None]]),
            Err(crate::runtime::ExecutionError::Deterministic(e)) => {
                tracing::error!("counter increment error: {e}");
                Ok(vec![vec![Some(anyhow::anyhow!("{e:#}"))]])
            }
            Err(crate::runtime::ExecutionError::NonDeterministic(e)) => Err(e),
        }
    }

    async fn replay_blocks_after(&mut self, after_height: u64) -> anyhow::Result<()> {
        let events = self.mock_bitcoin.lock().unwrap().get_all_block_events();
        for event in events {
            if let crate::bitcoin_follower::event::BlockEvent::BlockInsert { block, .. } = &event
                && block.height > after_height
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
            op_return_raw: None,
        })
    }
}
